package approval

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/decision"
)

func TestWriteLoadKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approver.key")
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, priv); err != nil {
		t.Fatalf("WriteKeyFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	got, err := LoadKeyFile(path)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	gotPub := got.Public().(ed25519.PublicKey)
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("loaded key does not match generated key")
	}
	if Kid(gotPub) != Kid(pub) {
		t.Fatalf("Kid mismatch after round trip")
	}
}

func TestWriteKeyFileRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approver.key")
	_, priv, _ := GenerateKey()
	if err := WriteKeyFile(path, priv); err != nil {
		t.Fatal(err)
	}
	_, priv2, _ := GenerateKey()
	if err := WriteKeyFile(path, priv2); err == nil {
		t.Fatal("WriteKeyFile overwrote an existing key")
	}
}

func TestLoadKeyFileRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approver.key")
	_, priv, _ := GenerateKey()
	if err := WriteKeyFile(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("LoadKeyFile accepted a 0644 key file")
	}
}

func TestApproverKeyFileIsNotADecisionKeyFile(t *testing.T) {
	approverPath := filepath.Join(t.TempDir(), "approver.key")
	decisionPath := filepath.Join(t.TempDir(), "decision.key")
	_, approverPriv, _ := GenerateKey()
	_, decisionPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(approverPath, approverPriv); err != nil {
		t.Fatal(err)
	}
	if err := decision.WriteKeyFile(decisionPath, decisionPriv); err != nil {
		t.Fatal(err)
	}
	// An approver key file must not load as a decision key, and vice versa.
	if _, err := decision.LoadKeyFile(approverPath); err == nil {
		t.Fatal("decision.LoadKeyFile accepted an approver key file")
	}
	if _, err := LoadKeyFile(decisionPath); err == nil {
		t.Fatal("approval.LoadKeyFile accepted a decision key file")
	}
}

func TestKidMatchesDecisionKidConstruction(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if Kid(pub) != decision.Kid(pub) {
		t.Fatal("approval.Kid must use the same RFC 7638 thumbprint construction as decision.Kid")
	}
}
