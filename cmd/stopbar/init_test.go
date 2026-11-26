package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/examples/policies"
	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/policy"
	"github.com/NikhilSetiya/stopbar/internal/signer"
)

// TestInitTree checks that every generated file loads through the same
// loader stopbard uses, secrets are 0600, and the config starts secure.
func TestInitTree(t *testing.T) {
	for _, tc := range []struct {
		name, chain, rpc string
		wantRPC          string
	}{
		{"dev", "dev", "", ""},
		{"base", "base", "", "https://mainnet.base.org"},
		{"base-sepolia custom rpc", "base-sepolia", "http://127.0.0.1:8545", "http://127.0.0.1:8545"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "sb")
			args := []string{"--dir", dir, "--chain", tc.chain}
			if tc.rpc != "" {
				args = append(args, "--rpc", tc.rpc)
			}
			if err := initCmd(args); err != nil {
				t.Fatalf("init: %v", err)
			}
			p := func(n string) string { return filepath.Join(dir, n) }
			for _, f := range []string{"stopbard.json", "world.json", "decision.key", "wallet.key", "api-keys.json", "approvers.json", "approver-1.key", "approver-2.key"} {
				fi, err := os.Stat(p(f))
				if err != nil || fi.Mode().Perm() != 0o600 {
					t.Errorf("%s: mode %v, err %v; want 0600", f, fi.Mode().Perm(), err)
				}
			}
			if fi, err := os.Stat(p("state")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Errorf("state dir: %v %v", fi, err)
			}

			var cfg map[string]any
			b, _ := os.ReadFile(p("stopbard.json"))
			if err := json.Unmarshal(b, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg["listen"] != "127.0.0.1:7777" || cfg["auth_keys"] != p("api-keys.json") || cfg["approvers"] != p("approvers.json") ||
				cfg["approval_quorum"] != 2.0 || cfg["breaker_quorum"] != 2.0 || cfg["dev_wallet"] != p("wallet.key") {
				t.Errorf("config not secure/complete: %v", cfg)
			}

			if _, err := policy.Load(p("policies")); err != nil {
				t.Errorf("policies: %v", err)
			}
			bundle, _ := fs.ReadDir(policies.FS, ".")
			for _, e := range bundle { // the starter pack, byte for byte (not a fork)
				want, _ := os.ReadFile(filepath.Join("..", "..", "examples", "policies", e.Name()))
				got, _ := os.ReadFile(filepath.Join(p("policies"), e.Name()))
				if len(want) == 0 || !bytes.Equal(got, want) {
					t.Errorf("policies/%s differs from examples/policies", e.Name())
				}
			}
			w, err := devstub.LoadWorld(p("world.json"))
			if err != nil {
				t.Fatalf("world: %v", err)
			}
			if w.ChainRPC != tc.wantRPC || len(w.Limits) != len(devstub.DefaultLimits) || (tc.chain != "dev") != (len(w.Feeds) > 0) {
				t.Errorf("world: rpc %q feeds %d limits %d", w.ChainRPC, len(w.Feeds), len(w.Limits))
			}
			if _, err := decision.LoadKeyFile(p("decision.key")); err != nil {
				t.Errorf("decision key: %v", err)
			}
			if _, err := signer.LoadDevWallet(p("wallet.key")); err != nil {
				t.Errorf("wallet: %v", err)
			}
			if _, err := auth.LoadKeyStore(p("api-keys.json")); err != nil {
				t.Errorf("api keys: %v", err)
			}
			var recs []map[string]any
			b, _ = os.ReadFile(p("api-keys.json"))
			_ = json.Unmarshal(b, &recs)
			if len(recs) != 1 || recs[0]["tenant"] != "demo" || recs[0]["agent_id"] != "wallet-agent" || len(recs[0]["scopes"].([]any)) != 1 || recs[0]["scopes"].([]any)[0] != "evaluate" {
				t.Errorf("api key record: %v", recs)
			}
			ks, err := approval.LoadConfigFile(p("approvers.json"))
			if err != nil || ks.Len() != 2 {
				t.Fatalf("approvers: %v (len %d)", err, ks.Len())
			}
			for _, f := range []string{"approver-1.key", "approver-2.key"} {
				priv, err := approval.LoadKeyFile(p(f))
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				if k, ok := ks.Lookup(approval.Kid(priv.Public().(ed25519.PublicKey))); !ok || k.Owner.AgentID == "wallet-agent" {
					t.Errorf("%s: not configured, or owned by the agent: %+v", f, k)
				}
			}
		})
	}
}

func TestInitRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown persona", []string{"--persona", "custody"}, "unknown persona"},
		{"unknown chain", []string{"--chain", "solana"}, "unknown --chain"},
		{"rpc with dev", []string{"--rpc", "http://x"}, "--rpc needs"},
		{"empty tenant", []string{"--tenant", ""}, "must not be empty"},
		{"stray arg", []string{"extra"}, "usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := initCmd(append([]string{"--dir", t.TempDir()}, tc.args...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want %q", err, tc.want)
			}
		})
	}
}

func TestInitOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := initCmd([]string{"--dir", dir}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "decision.key"))
	if err := initCmd([]string{"--dir", dir}); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second init: %v; want a refusal", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "decision.key")); !bytes.Equal(before, after) {
		t.Fatal("a refused init changed the decision key")
	}
	if err := os.Chmod(filepath.Join(dir, "wallet.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initCmd([]string{"--dir", dir, "--force"}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "decision.key")); bytes.Equal(before, after) {
		t.Fatal("--force kept the old decision key")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "wallet.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("--force left wallet.key at %v", fi.Mode().Perm())
	}
	db := filepath.Join(dir, "state", "state.db")
	if err := os.WriteFile(db, []byte("audit"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := initCmd([]string{"--dir", dir, "--force"}); err == nil || !strings.Contains(err.Error(), "state.db") {
		t.Fatalf("--force over state.db: %v; want a refusal", err)
	}
	if b, _ := os.ReadFile(db); string(b) != "audit" {
		t.Fatal("init touched state.db")
	}
}
