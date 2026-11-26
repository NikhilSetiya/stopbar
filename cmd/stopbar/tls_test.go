package main

import (
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/auth/authtest"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
)

// TestMTLSFlags: --cert/--cert-key/--cacert make the CLI present its client
// certificate to a stopbard-style mTLS listener.
func TestMTLSFlags(t *testing.T) {
	defer func() { apiClient = http.DefaultClient }()
	dir := t.TempDir()
	ca := authtest.NewCA(t, "ca")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no cert", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(r.TLS.PeerCertificates[0].URIs[0].String()))
	}))
	srv.TLS = gateway.ServerTLSConfig(ca.Issue(t, authtest.Leaf{IPs: []net.IP{net.IPv4(127, 0, 0, 1)}}), ca.Pool())
	srv.StartTLS()
	defer srv.Close()
	cert, key := authtest.WriteKeyPair(t, ca.Issue(t, authtest.Leaf{URIs: []string{"spiffe://acme/ops"}}), dir, "ops")
	caPath := ca.WritePEM(t, dir, "ca.pem")

	parse := func(args ...string) error {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		use := mtlsFlags(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		return use()
	}
	for name, args := range map[string][]string{
		"cert without key": {"--cert", cert},
		"key without cert": {"--cert-key", key},
		"bad CA":           {"--cacert", key},
		"missing cert":     {"--cert", dir + "/nope", "--cert-key", key},
	} {
		if err := parse(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := parse("--cert", cert, "--cert-key", key, "--cacert", caPath); err != nil {
		t.Fatal(err)
	}
	status, body, err := callAPI(http.MethodGet, srv.URL+"/", "", nil)
	if err != nil || status != http.StatusOK || string(body) != "spiffe://acme/ops" {
		t.Fatalf("mTLS call: %d %q %v", status, body, err)
	}
}
