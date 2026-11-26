package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth/authtest"
)

func TestLoadMTLS(t *testing.T) {
	dir := t.TempDir()
	ca := authtest.NewCA(t, "ca")
	caPath := ca.WritePEM(t, dir, "ca.pem")
	cert, key := authtest.WriteKeyPair(t, ca.Issue(t, authtest.Leaf{DNSNames: []string{"stopbard"}}), dir, "server")
	expCert, expKey := authtest.WriteKeyPair(t, ca.Issue(t, authtest.Leaf{NotAfter: time.Now().Add(-time.Hour)}), dir, "expired")
	ids := filepath.Join(dir, "ids.json")
	if err := os.WriteFile(ids, []byte(`[{"spiffe_id":"spiffe://acme/bot","tenant":"acme","agent_id":"bot","scopes":["evaluate"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	openKey := filepath.Join(dir, "open.key")
	b, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openKey, b, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	good := tlsOpts{cert: cert, key: key, clientCA: caPath, identities: ids}
	with := func(f func(*tlsOpts)) tlsOpts { o := good; f(&o); return o }

	if cfg, a, err := loadMTLS(tlsOpts{}, false, time.Now()); cfg != nil || a != nil || err != nil {
		t.Errorf("mTLS off: %v %v %v", cfg, a, err)
	}
	if cfg, a, err := loadMTLS(good, false, time.Now()); cfg == nil || a == nil || err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, tc := range map[string]struct {
		o       tlsOpts
		apiKeys bool
	}{
		"TLS without client CA":      {with(func(o *tlsOpts) { o.clientCA = "" }), false},
		"TLS without identities":     {with(func(o *tlsOpts) { o.identities = "" }), false},
		"client CA without TLS cert": {tlsOpts{clientCA: caPath, identities: ids}, false},
		"cert without key":           {with(func(o *tlsOpts) { o.key = "" }), false},
		"with API keys":              {good, true},
		"missing cert":               {with(func(o *tlsOpts) { o.cert = missing }), false},
		"missing key":                {with(func(o *tlsOpts) { o.key = missing }), false},
		"world-readable key":         {with(func(o *tlsOpts) { o.key = openKey }), false},
		"cert/key mismatch":          {with(func(o *tlsOpts) { o.key = expKey }), false},
		"expired server cert":        {with(func(o *tlsOpts) { o.cert, o.key = expCert, expKey }), false},
		"missing client CA":          {with(func(o *tlsOpts) { o.clientCA = missing }), false},
		"client CA not a cert":       {with(func(o *tlsOpts) { o.clientCA = key }), false},
		"missing identities":         {with(func(o *tlsOpts) { o.identities = missing }), false},
		"identities not JSON":        {with(func(o *tlsOpts) { o.identities = caPath }), false},
	} {
		if _, _, err := loadMTLS(tc.o, tc.apiKeys, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
