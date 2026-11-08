package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/decision"
)

func TestKeygenDecisionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decision.key")
	if err := keygenCmd([]string{"decision-key", path}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := decision.LoadKeyFile(path) // must load as a real decision key
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	// refuses to overwrite an existing key
	if err := keygenCmd([]string{"decision-key", path}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	// one-shot verify derives exactly this key (same kid), from the file alone
	keys, err := verifyKeys("", path)
	if err != nil {
		t.Fatalf("verifyKeys(--decision-key): %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, ok := keys[decision.Kid(pub)]; !ok || len(keys) != 1 {
		t.Fatalf("verifyKeys derived %d keys; want the one with kid %s", len(keys), decision.Kid(pub))
	}
}

func TestVerifyKeysExclusive(t *testing.T) {
	if _, err := verifyKeys("", ""); err == nil {
		t.Fatal("neither --keys nor --decision-key should error")
	}
	if _, err := verifyKeys("a", "b"); err == nil {
		t.Fatal("both --keys and --decision-key should error")
	}
}

func TestKeygenApiKeyRequiresTenant(t *testing.T) {
	if err := keygenCmd([]string{"api-key"}); err == nil {
		t.Fatal("api-key without --tenant should error")
	}
	if err := keygenCmd([]string{"api-key", "--tenant", "demo"}); err != nil {
		t.Fatalf("api-key: %v", err)
	}
}
