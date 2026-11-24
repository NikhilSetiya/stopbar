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
	"slices"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// fakeBreaker is a 2-of-N breaker for tenant "acme". It does not verify
// Ed25519 signatures itself (that is internal/limiter's job, tested there);
// it only checks the envelope's own fields, exactly as the gateway's HTTP
// wiring is meant to be tested independently of cryptography.
type fakeBreaker struct {
	open  bool
	votes []string // kids counted so far
	ids   []auth.Identity
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

func (f *fakeBreaker) ResetBreaker(ctx context.Context, tenant string, sig approval.SignedBreakerReset) (model.BreakerStatus, error) {
	id, _ := auth.FromContext(ctx)
	f.ids = append(f.ids, id)
	if !f.open || tenant != "acme" {
		return f.BreakerStatus(tenant), model.ErrBreakerNotOpen
	}
	switch {
	case sig.Tenant != tenant:
		return f.BreakerStatus(tenant), &approval.VerifyError{Code: approval.CodeWrongTenant}
	case sig.Decision != approval.ResetDecision:
		return f.BreakerStatus(tenant), &approval.VerifyError{Code: approval.CodeBadDecision}
	case sig.Kid == "":
		return f.BreakerStatus(tenant), &approval.VerifyError{Code: approval.CodeUnknownKey}
	}
	if slices.Contains(f.votes, sig.Kid) {
		return f.BreakerStatus(tenant), model.ErrDuplicateVote
	}
	f.votes = append(f.votes, sig.Kid)
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
	return callBody(t, h, method, path, secret, nil)
}

// callBody is call with a request body (CS-151: POSTing a signed envelope).
func callBody(t *testing.T, h http.Handler, method, path, secret string, body []byte) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, b
}

// resetBody is the JSON body of a (not necessarily cryptographically valid —
// the fakeBreaker never checks the signature bytes) breaker-reset envelope.
func resetBody(t *testing.T, kid, tenant, decision string) []byte {
	t.Helper()
	b, err := json.Marshal(approval.SignedBreakerReset{
		BreakerResetObject: approval.BreakerResetObject{
			Tenant: tenant, TripRequestID: "req_1", Decision: decision, Expiry: time.Now().Add(time.Minute).Unix(),
		},
		Kid: kid, Sig: "ZmFrZS1zaWduYXR1cmUtNjQtYnl0ZXMtcGFkZGVkLW91dC1mb3ItdGhlLWZha2UtYnJlYWtlci4",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBreakerEndpoints(t *testing.T) {
	ks := approverKeys(t, map[string][3]string{
		"sk_alice": {"ak_alice", "acme", ApproveScope},
		"sk_bob":   {"ak_bob", "acme", ApproveScope},
		"sk_agent": {"ak_agent", "acme", EvalScope},
		"sk_evil":  {"ak_evil", "evil", ApproveScope},
	})
	fb := &fakeBreaker{open: true}
	gw := newGW(Config{Breaker: fb, Authenticator: BearerAuthenticator{Store: ks}})
	const reset = "/v1/breakers/acme/reset"

	// CS-151: authorization is the signature, not the API key's scope or
	// tenant — any authenticated key may submit a vote (here, one with no
	// "approve" scope at all). A missing credential is still refused: an API
	// key is still required to identify the HTTP caller.
	if status, b := callBody(t, gw, http.MethodPost, reset, "", resetBody(t, "kid_alice", "acme", approval.ResetDecision)); status != http.StatusUnauthorized || errCode(t, b) != CodeUnauthenticated {
		t.Fatalf("no credential: %d %s", status, b)
	}

	// A signature for the wrong tenant is refused (400 INVALID_SIGNATURE),
	// even though the calling API key is of tenant "acme".
	if status, b := callBody(t, gw, http.MethodPost, reset, "sk_alice", resetBody(t, "kid_alice", "evil", approval.ResetDecision)); status != http.StatusBadRequest || errCode(t, b) != CodeInvalidSignature {
		t.Fatalf("wrong-tenant signature: %d %s", status, b)
	}

	// Insufficient signatures: one approver is 202, breaker still open; the
	// same owner (by kid, in this fake) again is refused (409 DUPLICATE_VOTE).
	// Note the voting key (sk_agent) carries only the "evaluate" scope: CS-151
	// authorization is the signature, so this succeeds.
	status, b := callBody(t, gw, http.MethodPost, reset, "sk_agent", resetBody(t, "kid_alice", "acme", approval.ResetDecision))
	var st model.BreakerStatus
	if err := json.Unmarshal(b, &st); err != nil || status != http.StatusAccepted || !st.Open || len(st.Votes) != 1 {
		t.Fatalf("one vote: %d %s", status, b)
	}
	if status, b := callBody(t, gw, http.MethodPost, reset, "sk_agent", resetBody(t, "kid_alice", "acme", approval.ResetDecision)); status != http.StatusConflict || errCode(t, b) != CodeDuplicateVote {
		t.Fatalf("repeat vote: %d %s", status, b)
	}
	if status, b := call(t, gw, http.MethodGet, "/v1/breakers/acme", "sk_bob"); status != http.StatusOK || !json.Valid(b) {
		t.Fatalf("status: %d %s", status, b)
	}
	// Quorum: the second distinct kid closes it (200).
	status, b = callBody(t, gw, http.MethodPost, reset, "sk_bob", resetBody(t, "kid_bob", "acme", approval.ResetDecision))
	st = model.BreakerStatus{}
	if err := json.Unmarshal(b, &st); err != nil || status != http.StatusOK || st.Open || st.Validate() != nil {
		t.Fatalf("quorum vote: %d %s", status, b)
	}
	if id := fb.ids[len(fb.ids)-1]; id.KeyID != "ak_bob" {
		t.Fatalf("caller identity not in the reset's context: %+v", id)
	}
	if status, b := callBody(t, gw, http.MethodPost, reset, "sk_alice", resetBody(t, "kid_carol", "acme", approval.ResetDecision)); status != http.StatusNotFound || errCode(t, b) != CodeNotFound {
		t.Fatalf("reset of a closed breaker: %d %s", status, b)
	}
	// Reading status needs no particular scope either.
	if status, _ := call(t, gw, http.MethodGet, "/v1/breakers/acme", "sk_agent"); status != http.StatusOK {
		t.Fatalf("an agent key could not read breaker status: %d", status)
	}
}

func TestBreakerEndpointsWithoutAuthOrBreaker(t *testing.T) {
	fb := &fakeBreaker{open: true}
	open := newGW(Config{Breaker: fb})
	if status, b := call(t, open, http.MethodGet, "/v1/breakers/acme", ""); status != http.StatusOK || !json.Valid(b) {
		t.Fatalf("loopback-dev status: %d %s", status, b)
	}
	// CS-151: with auth off (loopback dev) a reset needs no credential at
	// all — only the signature, which the fake breaker here accepts.
	status, b := callBody(t, open, http.MethodPost, "/v1/breakers/acme/reset", "", resetBody(t, "kid_alice", "acme", approval.ResetDecision))
	var st model.BreakerStatus
	if err := json.Unmarshal(b, &st); err != nil || status != http.StatusAccepted || !st.Open {
		t.Fatalf("reset without auth: %d %s", status, b)
	}
	none := newGW(Config{})
	if status, _ := call(t, none, http.MethodGet, "/v1/breakers/acme", ""); status != http.StatusServiceUnavailable {
		t.Fatalf("status without a breaker: %d", status)
	}
}
