package auth_test

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/auth/authtest"
)

const botID = "spiffe://acme.test/agents/bot"

func certMap(t *testing.T, ca *authtest.CA, body string) *auth.CertMap {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ids.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := auth.LoadCertMap(p, ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCertMapIdentify(t *testing.T) {
	ca, other := authtest.NewCA(t, "client-ca"), authtest.NewCA(t, "other-ca")
	m := certMap(t, ca, `[{"spiffe_id":"`+botID+`","tenant":"acme","agent_id":"bot","scopes":["evaluate"]}]`)
	leaf := func(c *authtest.CA, l authtest.Leaf) []*x509.Certificate {
		return []*x509.Certificate{c.Issue(t, l).Leaf}
	}
	now := time.Now()

	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		ok    bool
	}{
		"valid":            {leaf(ca, authtest.Leaf{URIs: []string{botID}}), true},
		"expired":          {leaf(ca, authtest.Leaf{URIs: []string{botID}, NotAfter: now.Add(-time.Hour)}), false},
		"wrong CA":         {leaf(other, authtest.Leaf{URIs: []string{botID}}), false},
		"no SAN":           {leaf(ca, authtest.Leaf{}), false},
		"DNS SAN only":     {leaf(ca, authtest.Leaf{DNSNames: []string{"bot.acme.test"}}), false},
		"multiple SANs":    {leaf(ca, authtest.Leaf{URIs: []string{botID, "spiffe://acme.test/agents/other"}}), false},
		"unmapped":         {leaf(ca, authtest.Leaf{URIs: []string{"spiffe://acme.test/agents/other"}}), false},
		"not spiffe":       {leaf(ca, authtest.Leaf{URIs: []string{"https://acme.test/agents/bot"}}), false},
		"non-canonical":    {leaf(ca, authtest.Leaf{URIs: []string{"spiffe://ACME.test/agents/bot"}}), false},
		"CA leaf":          {leaf(ca, authtest.Leaf{URIs: []string{botID}, IsCA: true}), false},
		"server-only EKU":  {leaf(ca, authtest.Leaf{URIs: []string{botID}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}), false},
		"no certificate":   {nil, false},
		"self-signed peer": {[]*x509.Certificate{other.Cert}, false},
	} {
		id, err := m.Identify(tc.chain, now)
		if tc.ok {
			want := auth.Identity{Method: auth.MethodMTLS, Tenant: "acme", AgentID: "bot", Scopes: []string{"evaluate"}, KeyID: botID}
			if err != nil || !reflect.DeepEqual(id, want) {
				t.Errorf("%s: got %+v, %v; want %+v", name, id, err, want)
			}
			continue
		}
		if !errors.Is(err, auth.ErrUnauthenticated) || !reflect.DeepEqual(id, auth.Identity{}) {
			t.Errorf("%s: got %+v, %v; want ErrUnauthenticated and no identity", name, id, err)
		}
	}
}

func TestValidSPIFFEID(t *testing.T) {
	for s, ok := range map[string]bool{
		"spiffe://acme.test/agents/bot":      true,
		"spiffe://td/a":                      true,
		"spiffe://a-b_c.9/A.b-C_9/x":         true,
		"spiffe://acme.test":                 false,
		"spiffe://acme.test/":                false,
		"spiffe:///agents/bot":               false,
		"spiffe://Acme/bot":                  false,
		"spiffe://acme:443/bot":              false,
		"spiffe://user@acme/bot":             false,
		"spiffe://acme/bot?x=1":              false,
		"spiffe://acme/bot#f":                false,
		"spiffe://acme/a//b":                 false,
		"spiffe://acme/a/../b":               false,
		"spiffe://acme/./b":                  false,
		"spiffe://acme/b%41":                 false,
		"SPIFFE://acme/bot":                  false,
		"https://acme/bot":                   false,
		"":                                   false,
		"spiffe://acme/agents/bot/trailing/": false,
	} {
		if got := auth.ValidSPIFFEID(s); got != ok {
			t.Errorf("ValidSPIFFEID(%q) = %v, want %v", s, got, ok)
		}
	}
}

func TestLoadCertMapRejects(t *testing.T) {
	ca := authtest.NewCA(t, "ca")
	for name, body := range map[string]string{
		"empty":        `[]`,
		"no tenant":    `[{"spiffe_id":"` + botID + `"}]`,
		"bad id":       `[{"spiffe_id":"https://acme/bot","tenant":"acme"}]`,
		"duplicate id": `[{"spiffe_id":"` + botID + `","tenant":"a"},{"spiffe_id":"` + botID + `","tenant":"b"}]`,
		"not json":     `[{`,
	} {
		p := filepath.Join(t.TempDir(), "ids.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := auth.LoadCertMap(p, ca.Pool()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := auth.LoadCertMap(filepath.Join(t.TempDir(), "missing.json"), ca.Pool()); err == nil {
		t.Error("missing file: accepted")
	}
}

func TestLoadCertPool(t *testing.T) {
	dir := t.TempDir()
	ca := authtest.NewCA(t, "ca")
	if _, err := auth.LoadCertPool(ca.WritePEM(t, dir, "ca.pem")); err != nil {
		t.Fatalf("valid CA: %v", err)
	}
	c := ca.Issue(t, authtest.Leaf{})
	_, keyPath := authtest.WriteKeyPair(t, c, dir, "leaf")
	for name, path := range map[string]string{
		"missing":     filepath.Join(dir, "nope.pem"),
		"private key": keyPath,
		"empty":       write(t, dir, "empty.pem", ""),
		"garbage":     write(t, dir, "garbage.pem", "not a pem"),
		"bad cert":    write(t, dir, "bad.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
	} {
		if _, err := auth.LoadCertPool(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
