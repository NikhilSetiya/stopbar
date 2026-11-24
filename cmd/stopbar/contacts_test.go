package main

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// contacts add/list/remove edit the registry in the state file, audited;
// with --decision-key the change is covered by a signed checkpoint, so
// `audit verify --require-covered` passes right after it.
func TestContactsAddListRemove(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "state.db")) // a state file as stopbard leaves it
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	keyPath := filepath.Join(dir, "decision.key")
	if err := keygenCmd([]string{"decision-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) }
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runContacts(args, &out, now)
		return out.String(), err
	}
	const addr = "0x7a25a1c4e3b2d1f09876543210fedcba98760c21"

	if out, err := run("add", addr[2:], "--state-dir", dir, "--tenant", "acme"); err == nil {
		t.Fatalf("an address without 0x accepted: %s", out)
	}
	out, err := run("add", "0x"+strings.ToUpper(addr[2:]), "--state-dir", dir, "--tenant", "acme", "--label", "payroll", "--decision-key", keyPath)
	if err != nil || !strings.Contains(out, addr+": added") || !strings.Contains(out, "checkpoint signed") {
		t.Fatalf("add: %q %v", out, err)
	}
	if out, err := run("add", addr, "--state-dir", dir, "--tenant", "acme"); err != nil || !strings.Contains(out, "no change") {
		t.Fatalf("re-add: %q %v", out, err)
	}
	out, err = run("list", "--state-dir", dir, "--tenant", "acme")
	if err != nil || !strings.Contains(out, addr) || !strings.Contains(out, "payroll") || !strings.Contains(out, "1 known destinations") {
		t.Fatalf("list: %q %v", out, err)
	}
	if out, _ := run("list", "--state-dir", dir, "--tenant", "other"); !strings.Contains(out, "0 known destinations") {
		t.Fatalf("other tenant sees acme's registry: %q", out)
	}
	if out, err := run("remove", addr, "--state-dir", dir, "--tenant", "acme", "--decision-key", keyPath); err != nil || !strings.Contains(out, "removed") {
		t.Fatalf("remove: %q %v", out, err)
	}
	if out, _ := run("list", "--state-dir", dir, "--tenant", "acme"); !strings.Contains(out, "0 known destinations") {
		t.Fatalf("after remove: %q", out)
	}

	// Two changes, both audited and covered by signed checkpoints.
	priv, err := decision.LoadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	db, err = store.OpenReadOnly(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rep, err := audit.Verify(db, map[string]ed25519.PublicKey{decision.Kid(pub): pub}, 1, 0)
	if err != nil || rep.Records != 2 || rep.Uncovered != 0 {
		t.Fatalf("audit: %+v %v", rep, err)
	}

	for _, bad := range [][]string{{}, {"frob"}, {"add"}, {"add", addr}, {"list", "--state-dir", dir}, {"add", addr, "--tenant", "acme"}} {
		if _, err := run(bad...); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
	if _, err := run("add", addr, "--state-dir", t.TempDir(), "--tenant", "acme"); err == nil {
		t.Error("add with no state file: accepted (it must not create one)")
	}
}
