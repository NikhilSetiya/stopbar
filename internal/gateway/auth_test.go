package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

type auditFunc func(context.Context, model.AuditRecordType, any) error

func (f auditFunc) Append(ctx context.Context, t model.AuditRecordType, b any) error {
	return f(ctx, t, b)
}

func keyStore(t *testing.T, secret, tenant, agent string, scopes ...string) *auth.KeyStore {
	t.Helper()
	sum := sha256.Sum256([]byte(secret))
	rec := map[string]any{"id": "ak_demo", "tenant": tenant, "agent_id": agent, "scopes": scopes, "sha256": hex.EncodeToString(sum[:])}
	b, _ := json.Marshal([]any{rec})
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := auth.LoadKeyStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func doAuth(t testing.TB, h http.Handler, body []byte, authz string) (*http.Response, []byte) {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func TestAuthIdentityAndAudit(t *testing.T) {
	const secret = "stopbar_sk_demo_key"
	ks := keyStore(t, secret, "acme", "bot", EvalScope)

	var auditedType model.AuditRecordType
	var auditedBody any
	sink := auditFunc(func(_ context.Context, ty model.AuditRecordType, b any) error {
		auditedType, auditedBody = ty, b
		return nil
	})
	var gotIdentity auth.Identity
	eval := evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		gotIdentity, _ = auth.FromContext(ctx)
		return decide(model.Allow)(ctx, r)
	})
	gw := newGW(Config{Evaluator: eval, Nonces: alwaysFresh{}, Authenticator: BearerAuthenticator{Store: ks}, Audit: sink})

	match := mutate(t, func(m map[string]any) { m["tenant"] = "acme"; m["actor"].(map[string]any)["agent_id"] = "bot" })
	mismatch := mutate(t, func(m map[string]any) { m["tenant"] = "evil"; m["actor"].(map[string]any)["agent_id"] = "bot" })

	// missing and wrong credentials -> 401
	for _, authz := range []string{"", "Bearer wrong", "not-bearer"} {
		res, b := doAuth(t, gw, match, authz)
		if res.StatusCode != http.StatusUnauthorized || errCode(t, b) != CodeUnauthenticated {
			t.Fatalf("authz=%q: %d %s", authz, res.StatusCode, b)
		}
	}

	// body identity mismatch -> 403, and it is audited with the identity in the body
	res, b := doAuth(t, gw, mismatch, "Bearer "+secret)
	if res.StatusCode != http.StatusForbidden || errCode(t, b) != CodeIdentityMismatch {
		t.Fatalf("mismatch: %d %s", res.StatusCode, b)
	}
	if auditedType != model.AuditAuthReject {
		t.Fatalf("mismatch not audited as auth_reject: %q", auditedType)
	}
	if id, ok := auditedBody.(map[string]any)["identity"].(auth.Identity); !ok || id.Tenant != "acme" {
		t.Fatalf("audit body missing the authenticated identity: %+v", auditedBody)
	}

	// matching request is allowed, and the engine sees the identity in context
	res, _ = doAuth(t, gw, match, "Bearer "+secret)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("valid request status %d", res.StatusCode)
	}
	if gotIdentity.Tenant != "acme" || gotIdentity.AgentID != "bot" || !gotIdentity.HasScope(EvalScope) {
		t.Fatalf("identity not propagated to the engine: %+v", gotIdentity)
	}
}

func TestAuthScopeAndRateLimit(t *testing.T) {
	const secret = "stopbar_sk_scoped"
	// a key WITHOUT the evaluate scope -> 403 FORBIDDEN_SCOPE
	noScope := newGW(Config{Evaluator: decide(model.Allow), Nonces: alwaysFresh{},
		Authenticator: BearerAuthenticator{Store: keyStore(t, secret, "acme", "bot", "read")}})
	body := mutate(t, func(m map[string]any) { m["tenant"] = "acme"; m["actor"].(map[string]any)["agent_id"] = "bot" })
	res, b := doAuth(t, noScope, body, "Bearer "+secret)
	if res.StatusCode != http.StatusForbidden || errCode(t, b) != CodeForbiddenScope {
		t.Fatalf("missing scope: %d %s", res.StatusCode, b)
	}

	// per-identity rate limit: the second valid request in a minute is 429
	limited := newGW(Config{Evaluator: decide(model.Allow), Nonces: alwaysFresh{}, RatePerMin: 1,
		Authenticator: BearerAuthenticator{Store: keyStore(t, secret, "acme", "bot", EvalScope)}})
	if res, _ := doAuth(t, limited, body, "Bearer "+secret); res.StatusCode != http.StatusOK {
		t.Fatalf("first request status %d", res.StatusCode)
	}
	if res, b := doAuth(t, limited, body, "Bearer "+secret); res.StatusCode != http.StatusTooManyRequests || errCode(t, b) != CodeRateLimited {
		t.Fatalf("second request not rate-limited: %d %s", res.StatusCode, b)
	}
}
