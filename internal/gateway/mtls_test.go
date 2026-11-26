package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/auth/authtest"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// TestMTLSAuth serves the gateway over a real TLS listener with the
// stopbard listener config (ServerTLSConfig) and the mTLS authenticator.
func TestMTLSAuth(t *testing.T) {
	const bot = "spiffe://acme.test/agents/bot"
	ca, other := authtest.NewCA(t, "client-ca"), authtest.NewCA(t, "other-ca")
	ids := filepath.Join(t.TempDir(), "ids.json")
	if err := os.WriteFile(ids, []byte(`[{"spiffe_id":"`+bot+`","tenant":"acme","agent_id":"bot","scopes":["evaluate"]},
		{"spiffe_id":"spiffe://acme.test/agents/reader","tenant":"acme","agent_id":"reader","scopes":["read"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cm, err := auth.LoadCertMap(ids, ca.Pool())
	if err != nil {
		t.Fatal(err)
	}

	var gotIdentity auth.Identity
	eval := evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		gotIdentity, _ = auth.FromContext(ctx)
		return decide(model.Allow)(ctx, r)
	})
	var audited []auth.Identity
	sink := auditFunc(func(_ context.Context, _ model.AuditRecordType, b any) error {
		audited = append(audited, b.(map[string]any)["identity"].(auth.Identity))
		return nil
	})
	srv := httptest.NewUnstartedServer(newGW(Config{Evaluator: eval, Nonces: alwaysFresh{},
		Authenticator: MTLSAuthenticator{Map: cm}, Audit: sink}))
	serverCert := ca.Issue(t, authtest.Leaf{IPs: []net.IP{net.IPv4(127, 0, 0, 1)}})
	srv.TLS = ServerTLSConfig(serverCert, ca.Pool())
	srv.StartTLS()
	defer srv.Close()

	// GetClientCertificate always presents the cert: Go's default would
	// silently withhold one whose issuer the server does not list.
	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if len(certs) == 0 {
					return &tls.Certificate{}, nil
				}
				return &certs[0], nil
			}}}}
	}
	post := func(c *http.Client, body []byte) (int, []byte, error) {
		res, err := c.Post(srv.URL+"/v1/evaluate", "application/json", bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b, nil
	}
	match := mutate(t, func(m map[string]any) {
		m["tenant"] = "acme"
		m["actor"].(map[string]any)["agent_id"] = "bot"
		m["actor"].(map[string]any)["workload_identity"] = bot
	})
	otherAgent := mutate(t, func(m map[string]any) { m["tenant"] = "acme"; m["actor"].(map[string]any)["agent_id"] = "mallory" })

	botCert := ca.Issue(t, authtest.Leaf{URIs: []string{bot}})
	for name, tc := range map[string]struct {
		client *http.Client
		body   []byte
		status int
		code   Code
	}{
		"valid cert":             {client(botCert), match, http.StatusOK, ""},
		"no cert":                {client(), match, http.StatusUnauthorized, CodeUnauthenticated},
		"unmapped cert":          {client(ca.Issue(t, authtest.Leaf{URIs: []string{"spiffe://acme.test/agents/ghost"}})), match, http.StatusUnauthorized, CodeUnauthenticated},
		"no SAN":                 {client(ca.Issue(t, authtest.Leaf{})), match, http.StatusUnauthorized, CodeUnauthenticated},
		"body names other agent": {client(botCert), otherAgent, http.StatusForbidden, CodeIdentityMismatch},
		"body names other workload": {client(botCert), mutate(t, func(m map[string]any) {
			m["tenant"] = "acme"
			m["actor"].(map[string]any)["agent_id"] = "bot"
			m["actor"].(map[string]any)["workload_identity"] = "spiffe://acme.test/agents/other"
		}), http.StatusForbidden, CodeIdentityMismatch},
		"mapped without scope": {client(ca.Issue(t, authtest.Leaf{URIs: []string{"spiffe://acme.test/agents/reader"}})), mutate(t, func(m map[string]any) { m["tenant"] = "acme"; m["actor"].(map[string]any)["agent_id"] = "reader" }), http.StatusForbidden, CodeForbiddenScope},
	} {
		gotIdentity = auth.Identity{}
		status, b, err := post(tc.client, tc.body)
		if err != nil || status != tc.status || (tc.code != "" && errCode(t, b) != tc.code) {
			t.Errorf("%s: %d %s %v; want %d %s", name, status, b, err, tc.status, tc.code)
		}
		if name == "valid cert" {
			want := auth.Identity{Method: auth.MethodMTLS, Tenant: "acme", AgentID: "bot", Scopes: []string{EvalScope}, KeyID: bot}
			if !reflect.DeepEqual(gotIdentity, want) {
				t.Errorf("identity not propagated to the engine: %+v", gotIdentity)
			}
		}
	}
	// The identity-mismatch (agent, workload) and scope rejections are audited with the cert identity.
	if len(audited) != 3 || audited[0].Method != auth.MethodMTLS || audited[0].KeyID == "" {
		t.Errorf("audited rejections: %+v", audited)
	}

	// A certificate from another CA, or an expired one, fails the handshake.
	for name, c := range map[string]tls.Certificate{
		"wrong CA": other.Issue(t, authtest.Leaf{URIs: []string{bot}}),
		"expired":  ca.Issue(t, authtest.Leaf{URIs: []string{bot}, NotAfter: time.Now().Add(-time.Hour)}),
	} {
		if status, _, err := post(client(c), match); err == nil {
			t.Errorf("%s: handshake succeeded (HTTP %d)", name, status)
		}
	}

	// Without TLS at all (a plaintext request reaching the handler) there is no identity.
	if _, err := (MTLSAuthenticator{Map: cm}).Authenticate(httptest.NewRequest("POST", "/v1/evaluate", nil)); err == nil {
		t.Error("plaintext request authenticated")
	}
}
