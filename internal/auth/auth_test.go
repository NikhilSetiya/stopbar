package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func hashOf(secret string) string {
	s := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(s[:])
}

func writeStore(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerify(t *testing.T) {
	store := `[{"id":"ak_1","tenant":"acme","agent_id":"bot","scopes":["evaluate"],"sha256":"` + hashOf("good") + `"},
	           {"id":"ak_2","tenant":"acme","agent_id":"old","scopes":["evaluate"],"sha256":"` + hashOf("revoked") + `","revoked":true}]`
	ks, err := LoadKeyStore(writeStore(t, store))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ks.Verify("good")
	if err != nil {
		t.Fatalf("good key: %v", err)
	}
	if id.Tenant != "acme" || id.AgentID != "bot" || !id.HasScope("evaluate") || id.HasScope("admin") {
		t.Fatalf("identity wrong: %+v", id)
	}
	for _, bad := range []string{"", "wrong", "revoked"} {
		if _, err := ks.Verify(bad); err != ErrUnauthenticated {
			t.Fatalf("Verify(%q) = %v, want ErrUnauthenticated", bad, err)
		}
	}
}

func TestLoadRejectsBadStore(t *testing.T) {
	for _, body := range []string{`[]`, `[{"id":"x","sha256":"short"}]`, `[{"tenant":"t","sha256":"` + hashOf("a") + `"},{"tenant":"t","sha256":"` + hashOf("a") + `"}]`} {
		if _, err := LoadKeyStore(writeStore(t, body)); err == nil {
			t.Fatalf("LoadKeyStore accepted a bad store: %s", body)
		}
	}
}

func TestContextRoundTrip(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context should carry no identity")
	}
	id := Identity{Method: MethodAPIKey, Tenant: "acme"}
	got, ok := FromContext(WithIdentity(context.Background(), id))
	if !ok || got.Tenant != "acme" {
		t.Fatalf("round-trip failed: %+v %v", got, ok)
	}
}
