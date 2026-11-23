package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// fakeBreaker is a 2-of-N breaker for tenant "acme".
type fakeBreaker struct {
	open  bool
	votes []string
	ids   []auth.Identity // identity seen in each reset's context
}

func (f *fakeBreaker) BreakerStatus(tenant string) model.BreakerStatus {
	st := model.BreakerStatus{Tenant: tenant, Votes: []model.BreakerVote{}, Quorum: 2}
	if f.open && tenant == "acme" {
		at := time.Unix(0, 0).UTC()
		st.Open, st.TrippedAt, st.TripRequestID, st.Reason = true, &at, "req_1", "tenant 1h USD cap 100 (circuit breaker)"
		for _, v := range f.votes {
			st.Votes = append(st.Votes, model.BreakerVote{Approver: v, At: at, ExpiresAt: at.Add(model.BreakerVoteTTL)})
		}
	}
	return st
}

func (f *fakeBreaker) ResetBreaker(ctx context.Context, tenant, approver string) (model.BreakerStatus, error) {
	id, _ := auth.FromContext(ctx)
	f.ids = append(f.ids, id)
	if !f.open || tenant != "acme" {
		return f.BreakerStatus(tenant), model.ErrBreakerNotOpen
	}
	if slices.Contains(f.votes, approver) {
		return f.BreakerStatus(tenant), model.ErrDuplicateVote
	}
	f.votes = append(f.votes, approver)
	if len(f.votes) >= 2 {
		f.open, f.votes = false, nil
	}
	return f.BreakerStatus(tenant), nil
}

// approverKeys writes a key store with one key per {secret: [id, tenant, scope]}.
func approverKeys(t *testing.T, keys map[string][3]string) *auth.KeyStore {
	t.Helper()
	var recs []any
	for secret, k := range keys {
		sum := sha256.Sum256([]byte(secret))
		recs = append(recs, map[string]any{"id": k[0], "tenant": k[1], "scopes": []string{k[2]}, "sha256": hex.EncodeToString(sum[:])})
	}
	b, _ := json.Marshal(recs)
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

func call(t *testing.T, h http.Handler, method, path, secret string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, b
}

func TestBreakerEndpoints(t *testing.T) {
	ks := approverKeys(t, map[string][3]string{
		"sk_alice": {"ak_alice", "acme", ApproveScope},
		"sk_bob":   {"ak_bob", "acme", ApproveScope},
		"sk_agent": {"ak_agent", "acme", EvalScope},
		"sk_evil":  {"ak_evil", "evil", ApproveScope},
	})
	var audited []string
	sink := auditFunc(func(_ context.Context, ty model.AuditRecordType, b any) error {
		audited = append(audited, string(ty)+": "+b.(map[string]any)["reason"].(string))
		return nil
	})
	fb := &fakeBreaker{open: true}
	gw := newGW(Config{Breaker: fb, Authenticator: BearerAuthenticator{Store: ks}, Audit: sink})
	const reset = "/v1/breakers/acme/reset"

	for _, c := range []struct {
		name, secret string
		status       int
		code         Code
	}{
		{"no credential", "", http.StatusUnauthorized, CodeUnauthenticated},
		{"agent key (no approve scope)", "sk_agent", http.StatusForbidden, CodeForbiddenScope},
		{"another tenant's approver", "sk_evil", http.StatusForbidden, CodeIdentityMismatch},
	} {
		status, b := call(t, gw, http.MethodPost, reset, c.secret)
		if status != c.status || errCode(t, b) != c.code {
			t.Fatalf("%s: %d %s, want %d %s", c.name, status, b, c.status, c.code)
		}
	}
	if len(audited) != 2 || len(fb.votes) != 0 {
		t.Fatalf("rejections audited %v, votes %v", audited, fb.votes)
	}

	// Insufficient signatures: one approver is 202, breaker still open; the
	// same approver again is refused (409 DUPLICATE_VOTE).
	status, b := call(t, gw, http.MethodPost, reset, "sk_alice")
	var st model.BreakerStatus
	if err := json.Unmarshal(b, &st); err != nil || status != http.StatusAccepted || !st.Open || len(st.Votes) != 1 {
		t.Fatalf("one vote: %d %s", status, b)
	}
	if status, b := call(t, gw, http.MethodPost, reset, "sk_alice"); status != http.StatusConflict || errCode(t, b) != CodeDuplicateVote {
		t.Fatalf("repeat vote: %d %s", status, b)
	}
	if status, b := call(t, gw, http.MethodGet, "/v1/breakers/acme", "sk_bob"); status != http.StatusOK || !json.Valid(b) {
		t.Fatalf("status: %d %s", status, b)
	}
	// Quorum: the second distinct approver closes it (200).
	status, b = call(t, gw, http.MethodPost, reset, "sk_bob")
	st = model.BreakerStatus{}
	if err := json.Unmarshal(b, &st); err != nil || status != http.StatusOK || st.Open || st.Validate() != nil {
		t.Fatalf("quorum vote: %d %s", status, b)
	}
	if id := fb.ids[len(fb.ids)-1]; id.KeyID != "ak_bob" {
		t.Fatalf("approver identity not in the reset's context: %+v", id)
	}
	if status, b := call(t, gw, http.MethodPost, reset, "sk_alice"); status != http.StatusNotFound || errCode(t, b) != CodeNotFound {
		t.Fatalf("reset of a closed breaker: %d %s", status, b)
	}
	if status, _ := call(t, gw, http.MethodGet, "/v1/breakers/acme", "sk_agent"); status != http.StatusForbidden {
		t.Fatalf("an agent key read breaker status: %d", status)
	}
}

func TestBreakerEndpointsWithoutAuthOrBreaker(t *testing.T) {
	fb := &fakeBreaker{open: true}
	open := newGW(Config{Breaker: fb})
	if status, b := call(t, open, http.MethodGet, "/v1/breakers/acme", ""); status != http.StatusOK || !json.Valid(b) {
		t.Fatalf("loopback-dev status: %d %s", status, b)
	}
	// Votes need identities: no auth, no reset.
	if status, b := call(t, open, http.MethodPost, "/v1/breakers/acme/reset", ""); status != http.StatusServiceUnavailable || errCode(t, b) != CodeEngineUnavailable {
		t.Fatalf("reset without auth: %d %s", status, b)
	}
	none := newGW(Config{})
	if status, _ := call(t, none, http.MethodGet, "/v1/breakers/acme", ""); status != http.StatusServiceUnavailable {
		t.Fatalf("status without a breaker: %d", status)
	}
}
