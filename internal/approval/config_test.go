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
		{"id":"alice","tenant":"acme","public_key":"%s"},
		{"id":"bob","tenant":"acme","agent_id":"bob-agent","public_key":"%s"}
	]}`, b64.EncodeToString(pub1), b64.EncodeToString(pub2))
	ks, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if ks.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", ks.Len())
	}
	k, ok := ks.Lookup(Kid(pub1))
	if !ok || k.ID != "alice" || k.Tenant != "acme" {
		t.Fatalf("Lookup(alice) = %+v, %v", k, ok)
	}
	k2, ok := ks.Lookup(Kid(pub2))
	if !ok || k2.AgentID != "bob-agent" {
		t.Fatalf("Lookup(bob) = %+v, %v", k2, ok)
	}
}

func TestParseConfigRejects(t *testing.T) {
	pub, _, _ := GenerateKey()
	validKey := b64.EncodeToString(pub)
	cases := []struct {
		name string
		doc  string
	}{
		{"empty", `{"approvers":[]}`},
		{"missing id", fmt.Sprintf(`{"approvers":[{"tenant":"acme","public_key":"%s"}]}`, validKey)},
		{"missing tenant", fmt.Sprintf(`{"approvers":[{"id":"alice","public_key":"%s"}]}`, validKey)},
		{"bad public key encoding", `{"approvers":[{"id":"alice","tenant":"acme","public_key":"not-base64url!!"}]}`},
		{"short public key", `{"approvers":[{"id":"alice","tenant":"acme","public_key":"YWJj"}]}`},
		{"unknown field", fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","public_key":"%s","extra":"x"}]}`, validKey)},
		{"malformed json", `{`},
		{"duplicate key across entries", fmt.Sprintf(`{"approvers":[
			{"id":"alice","tenant":"acme","public_key":"%s"},
			{"id":"alice2","tenant":"other","public_key":"%s"}
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

func TestLoadConfigFile(t *testing.T) {
	path := t.TempDir() + "/approvers.json"
	pub, _, _ := GenerateKey()
	doc := fmt.Sprintf(`{"approvers":[{"id":"alice","tenant":"acme","public_key":"%s"}]}`, b64.EncodeToString(pub))
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
