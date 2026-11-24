package approval

import (
	"fmt"
	"os"
	"testing"
)

func TestParseConfigValid(t *testing.T) {
	pub1, _, _ := GenerateKey()
	pub2, _, _ := GenerateKey()
	doc := fmt.Sprintf(`{"approvers":[
		{"id":"alice","tenant":"acme","owner":{"key_id":"ak_alice"},"public_key":"%s"},
		{"id":"bob","tenant":"acme","owner":{"agent_id":"bob-agent"},"public_key":"%s"}
	]}`, b64.EncodeToString(pub1), b64.EncodeToString(pub2))
	ks, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if ks.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", ks.Len())
	}
	k, ok := ks.Lookup(Kid(pub1))
	if !ok || k.ID != "alice" || k.Tenant != "acme" || k.Owner.KeyID != "ak_alice" {
		t.Fatalf("Lookup(alice) = %+v, %v", k, ok)
	}
	k2, ok := ks.Lookup(Kid(pub2))
	if !ok || k2.Owner.AgentID != "bob-agent" {
		t.Fatalf("Lookup(bob) = %+v, %v", k2, ok)
	}
}

func TestParseConfigValidOwnerWithBothFields(t *testing.T) {
	pub, _, _ := GenerateKey()
	doc := fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","owner":{"agent_id":"alice-agent","key_id":"ak_alice"},"public_key":"%s"}]}`, b64.EncodeToString(pub))
	ks, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	k, _ := ks.Lookup(Kid(pub))
	if k.Owner.AgentID != "alice-agent" || k.Owner.KeyID != "ak_alice" {
		t.Fatalf("Owner = %+v", k.Owner)
	}
}

func TestParseConfigRejects(t *testing.T) {
	pub, _, _ := GenerateKey()
	validKey := b64.EncodeToString(pub)
	owner := `"owner":{"key_id":"ak_x"}`
	cases := []struct {
		name string
		doc  string
	}{
		{"empty", `{"approvers":[]}`},
		{"missing id", fmt.Sprintf(`{"approvers":[{"tenant":"acme",%s,"public_key":"%s"}]}`, owner, validKey)},
		{"missing tenant", fmt.Sprintf(`{"approvers":[{"id":"alice",%s,"public_key":"%s"}]}`, owner, validKey)},
		{"missing owner", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","public_key":"%s"}]}`, validKey)},
		{"owner with neither field set", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","owner":{},"public_key":"%s"}]}`, validKey)},
		{"owner with empty-string fields", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","owner":{"agent_id":"","key_id":""},"public_key":"%s"}]}`, validKey)},
		{"bad public key encoding", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme",%s,"public_key":"not-base64url!!"}]}`, owner)},
		{"short public key", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme",%s,"public_key":"YWJj"}]}`, owner)},
		{"unknown field", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme",%s,"public_key":"%s","extra":"x"}]}`, owner, validKey)},
		{"malformed json", `{`},
		{"duplicate key across entries", fmt.Sprintf(`{"approvers":[
			{"id":"alice","tenant":"acme","owner":{"key_id":"ak_alice"},"public_key":"%s"},
			{"id":"alice2","tenant":"other","owner":{"key_id":"ak_alice2"},"public_key":"%s"}
		]}`, validKey, validKey)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(c.doc)); err == nil {
				t.Fatalf("ParseConfig(%s) did not error", c.name)
			}
		})
	}
}

// TestNewKeySetRejectsMissingOwner guards the rule at its other entry point:
// a Key built directly (not through ParseConfig) with no Owner is refused
// too, so the requirement cannot be bypassed by callers that skip the JSON
// config path.
func TestNewKeySetRejectsMissingOwner(t *testing.T) {
	pub, _, _ := GenerateKey()
	_, err := NewKeySet([]Key{{ID: "alice", Tenant: "acme", Public: pub}})
	if err == nil {
		t.Fatal("NewKeySet accepted a key with no Owner")
	}
}

func TestNewKeySetRejectsDuplicateKid(t *testing.T) {
	pub, _, _ := GenerateKey()
	keys := []Key{
		{ID: "alice", Tenant: "acme", Owner: Owner{KeyID: "ak_alice"}, Public: pub},
		{ID: "alice-again", Tenant: "other-tenant", Owner: Owner{KeyID: "ak_alice2"}, Public: pub},
	}
	if _, err := NewKeySet(keys); err == nil {
		t.Fatal("NewKeySet accepted two entries sharing a kid")
	}
}

func TestLoadConfigFile(t *testing.T) {
	path := t.TempDir() + "/approvers.json"
	pub, _, _ := GenerateKey()
	doc := fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","owner":{"key_id":"ak_alice"},"public_key":"%s"}]}`, b64.EncodeToString(pub))
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if ks.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", ks.Len())
	}
}
