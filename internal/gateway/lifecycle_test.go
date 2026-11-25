package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Keys for the lifecycle tests: the requester agent, another agent of the same
// tenant, an approver, and a requester of another tenant.
const (
	skBot     = "stopbar_sk_bot"
	skOther   = "stopbar_sk_other"
	skOps     = "stopbar_sk_ops"
	skForeign = "stopbar_sk_foreign"
)

func lifecycleKeys(t *testing.T) *auth.KeyStore {
	t.Helper()
	rec := func(id, secret, tenant, agent string, scopes ...string) map[string]any {
		sum := sha256.Sum256([]byte(secret))
		return map[string]any{"id": id, "tenant": tenant, "agent_id": agent, "scopes": scopes, "sha256": hex.EncodeToString(sum[:])}
	}
	b, _ := json.Marshal([]any{
		rec("ak_bot", skBot, "acme", "bot", EvalScope),
		rec("ak_other", skOther, "acme", "other", EvalScope),
		rec("ak_ops", skOps, "acme", "", ApproveScope),
		rec("ak_foreign", skForeign, "evil", "bot", EvalScope),
	})
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

// fakeActions owns reservation "r1" for acme/bot and returns err from
// Commit/Release, recording what it was asked.
type fakeActions struct {
	mu       sync.Mutex
	err      error
	calls    []string
	identity auth.Identity
}

func (f *fakeActions) Owner(id string) (string, string, bool) {
	return "acme", "bot", id == "r1"
}
func (f *fakeActions) Commit(ctx context.Context, id, txRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity, _ = auth.FromContext(ctx)
	f.calls = append(f.calls, "commit "+id+" "+txRef)
	return f.err
}
func (f *fakeActions) Release(ctx context.Context, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity, _ = auth.FromContext(ctx)
	f.calls = append(f.calls, "release "+id+" "+reason)
	return f.err
}

// fakeApprover serves one escalation "e1" requested by acme/bot. It does not
// verify Ed25519 signatures itself (internal/approval and internal/engine
// cover that); it records the envelope it was given, for assertions.
type fakeApprover struct {
	state    model.EscalationState
	err      error
	sig      approval.SignedEscalation
	decision *model.Decision // Status's decision, when set
	verdict  *model.Decision // Approve's answer, when set (e.g. a refused signature's deny)
}

func (f *fakeApprover) Approve(_ context.Context, id string, sig approval.SignedEscalation) (model.Decision, error) {
	f.sig = sig
	if f.err != nil {
		return model.Decision{}, f.err
	}
	if f.verdict != nil {
		return *f.verdict, nil
	}
	return model.Decision{RequestID: id, Outcome: model.Allow}, nil
}
func (f *fakeApprover) Reject(_ context.Context, id string, sig approval.SignedEscalation) (model.Decision, error) {
	f.sig = sig
	if f.err != nil {
		return model.Decision{}, f.err
	}
	return model.Decision{RequestID: id, Outcome: model.Deny, Reasons: []model.Reason{{Code: "APPROVAL_REJECTED"}}}, nil
}
func (f *fakeApprover) Status(ctx context.Context, id string) (model.EscalationStatus, error) {
	if id != "e1" {
		return model.EscalationStatus{}, model.ErrNoPending
	}
	if f.err != nil {
		return model.EscalationStatus{}, f.err
	}
	return model.EscalationStatus{RequestID: id, State: f.state, Decision: f.decision,
		Request: model.ActionRequest{ID: id, Tenant: "acme", Actor: model.Actor{AgentID: "bot"}}}, nil
}

// escBody is the JSON body of an escalation approve/reject envelope for "e1"
// (not necessarily cryptographically valid — fakeApprover never checks the
// signature bytes, only internal/approval and internal/engine do that).
func escBody(t *testing.T, decision string) string {
	t.Helper()
	b, err := json.Marshal(approval.SignedEscalation{
		EscalationObject: approval.EscalationObject{
			EscalationID: "e1", PayloadHash: "sha256:" + strings.Repeat("a", 64), Decision: decision, Expiry: time.Now().Add(time.Minute).Unix(),
		},
		Kid: "kid_ops", Sig: "ZmFrZS1zaWduYXR1cmUtNjQtYnl0ZXMtcGFkZGVkLW91dC1mb3ItdGhlLWZha2UtYXBwcm92ZXIu",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func callJSON(t *testing.T, h http.Handler, method, path, secret, ctype, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw, _ := io.ReadAll(rec.Result().Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return rec.Code, out
}

func TestCommitRelease(t *testing.T) {
	const js = "application/json"
	var audited []string
	act := &fakeActions{}
	g := New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}, Actions: act,
		Audit: auditFunc(func(_ context.Context, typ model.AuditRecordType, b any) error {
			audited = append(audited, string(typ)+": "+b.(map[string]any)["reason"].(string))
			return nil
		})})

	cases := []struct {
		name, path, secret, ctype, body string
		err                             error
		status                          int
		code                            string
	}{
		{"commit", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0xabc"}`, nil, 200, ""},
		{"late commit still records the spend", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0xabc"}`, model.ErrReservationExpired, 200, ""},
		{"commit with another tx_ref", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0xdef"}`, model.ErrAlreadyCommitted, 409, "CONFLICT"},
		{"release", "/v1/actions/r1/release", skBot, js, `{"reason":"user cancelled"}`, nil, 200, ""},
		{"release with an empty body", "/v1/actions/r1/release", skBot, "", "", nil, 200, ""},
		{"release after commit", "/v1/actions/r1/release", skBot, "", "", model.ErrAlreadyCommitted, 409, "CONFLICT"},
		{"release of a lapsed reservation", "/v1/actions/r1/release", skBot, "", "", model.ErrReservationExpired, 410, "RESERVATION_EXPIRED"},
		{"released or never held", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0x1"}`, model.ErrUnknownReservation, 404, "NOT_FOUND"},
		{"store down", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0x1"}`, errors.New("disk"), 500, "INTERNAL"},
		{"unknown id", "/v1/actions/nope/commit", skBot, js, `{"tx_ref":"0x1"}`, nil, 404, "NOT_FOUND"},
		{"another agent's reservation", "/v1/actions/r1/release", skOther, "", "", nil, 404, "NOT_FOUND"},
		{"another tenant's reservation", "/v1/actions/r1/commit", skForeign, js, `{"tx_ref":"0x1"}`, nil, 404, "NOT_FOUND"},
		{"approver key lacks evaluate", "/v1/actions/r1/commit", skOps, js, `{"tx_ref":"0x1"}`, nil, 403, "FORBIDDEN_SCOPE"},
		{"no credential", "/v1/actions/r1/commit", "", js, `{"tx_ref":"0x1"}`, nil, 401, "UNAUTHENTICATED"},
		{"commit needs tx_ref", "/v1/actions/r1/commit", skBot, js, `{}`, nil, 400, "INVALID_REQUEST"},
		{"commit needs a body", "/v1/actions/r1/commit", skBot, "", "", nil, 400, "INVALID_REQUEST"},
		{"release takes no tx_ref", "/v1/actions/r1/release", skBot, js, `{"tx_ref":"0x1"}`, nil, 400, "INVALID_REQUEST"},
		{"unknown field", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0x1","extra":1}`, nil, 400, "UNKNOWN_FIELD"},
		{"case-folded key", "/v1/actions/r1/commit", skBot, js, `{"TX_REF":"0x1"}`, nil, 400, "UNKNOWN_FIELD"},
		{"duplicate key", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"0x1","tx_ref":"0x2"}`, nil, 400, "DUPLICATE_KEY"},
		{"not JSON", "/v1/actions/r1/commit", skBot, "text/plain", `tx_ref=0x1`, nil, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"oversized tx_ref", "/v1/actions/r1/commit", skBot, js, `{"tx_ref":"` + strings.Repeat("a", 300) + `"}`, nil, 400, "INVALID_REQUEST"},
		{"wrong method", "/v1/actions/r1/commit", skBot, "", "", nil, 405, "METHOD_NOT_ALLOWED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			act.err = c.err
			method := http.MethodPost
			if c.code == "METHOD_NOT_ALLOWED" {
				method = http.MethodGet
			}
			status, body := callJSON(t, g, method, c.path, c.secret, c.ctype, c.body)
			if status != c.status || (c.code != "" && body["code"] != c.code) {
				t.Fatalf("HTTP %d %v, want %d %s", status, body, c.status, c.code)
			}
			if status == 200 && (body["request_id"] != "r1" || act.identity.KeyID != "ak_bot") {
				t.Fatalf("body %v / identity %+v: want r1 settled as ak_bot", body, act.identity)
			}
		})
	}
	if !strings.Contains(strings.Join(audited, "\n"), "not the requester of this reservation") {
		t.Fatalf("a foreign settle attempt was not audited: %v", audited)
	}
	if last := act.calls[len(act.calls)-1]; !strings.HasPrefix(last, "commit r1") {
		t.Fatalf("calls %v", act.calls)
	}

	t.Run("disabled without auth or actions", func(t *testing.T) {
		for _, g := range []*Gateway{New(Config{Actions: act}), New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}})} {
			if status, body := callJSON(t, g, http.MethodPost, "/v1/actions/r1/release", skBot, "", ""); status != 503 {
				t.Fatalf("HTTP %d %v, want 503", status, body)
			}
		}
	})
}

func TestApprovalLifecycleRoutes(t *testing.T) {
	ap := &fakeApprover{state: model.EscalationPending}
	g := New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}, Approver: ap})

	t.Run("reject answers 403 with the deny, verifying the posted envelope", func(t *testing.T) {
		status, body := callJSON(t, g, http.MethodPost, "/v1/approvals/e1/reject", skOps, "application/json", escBody(t, approval.Reject))
		if status != 403 || body["outcome"] != "deny" || ap.sig.Kid != "kid_ops" || ap.sig.Decision != approval.Reject {
			t.Fatalf("HTTP %d %v sig %+v", status, body, ap.sig)
		}
	})
	// CS-151: authorization is the signature, not the API key's scope — any
	// authenticated key (here skBot, which has only "evaluate") may submit
	// a reject envelope; it is the engine/limiter that verifies it.
	for _, c := range []struct {
		name, path, secret, decision string
		err                          error
		status                       int
		code                         string
	}{
		{"approve resolved", "/v1/approvals/e1", skOps, approval.Approve, model.ErrResolved, 409, "ALREADY_RESOLVED"},
		{"reject resolved", "/v1/approvals/e1/reject", skOps, approval.Reject, model.ErrResolved, 409, "ALREADY_RESOLVED"},
		{"reject unknown", "/v1/approvals/e1/reject", skOps, approval.Reject, model.ErrNoPending, 404, "NOT_FOUND"},
		{"reject from a non-approve-scoped key still reaches the approver", "/v1/approvals/e1/reject", skBot, approval.Reject, nil, 403, ""},
		{"reject unauthenticated", "/v1/approvals/e1/reject", "", approval.Reject, nil, 401, "UNAUTHENTICATED"},
		{"reject store down", "/v1/approvals/e1/reject", skOps, approval.Reject, errors.New("disk"), 500, "INTERNAL"},
		{"duplicate vote", "/v1/approvals/e1/reject", skOps, approval.Reject, approval.ErrDuplicateVote, 409, "DUPLICATE_VOTE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ap.err = c.err
			body := escBody(t, c.decision)
			if c.secret == "" {
				body = "" // unauthenticated: never reaches body decoding
			}
			status, got := callJSON(t, g, http.MethodPost, c.path, c.secret, "application/json", body)
			if status != c.status || (c.code != "" && got["code"] != c.code) {
				t.Fatalf("HTTP %d %v, want %d %s", status, got, c.status, c.code)
			}
		})
	}
	ap.err = nil

	t.Run("poll status is as safe as evaluate's", func(t *testing.T) {
		for state, want := range map[model.EscalationState]int{
			model.EscalationPending: 202, model.EscalationAllowed: 200, model.EscalationDenied: 403, model.EscalationExpired: 403,
		} {
			ap.state = state
			for _, sk := range []string{skBot, skOps} { // the requester, and an approver
				status, body := callJSON(t, g, http.MethodGet, "/v1/decisions/e1", sk, "", "")
				if status != want || body["state"] != string(state) {
					t.Fatalf("%s as %s: HTTP %d %v, want %d", state, sk, status, body, want)
				}
			}
		}
	})
	t.Run("poll is hidden from other agents and unknown ids", func(t *testing.T) {
		for _, c := range []struct{ path, secret string }{
			{"/v1/decisions/e1", skOther}, {"/v1/decisions/nope", skBot},
		} {
			if status, body := callJSON(t, g, http.MethodGet, c.path, c.secret, "", ""); status != 404 {
				t.Fatalf("%s as %s: HTTP %d %v, want 404", c.path, c.secret, status, body)
			}
		}
		if status, _ := callJSON(t, g, http.MethodGet, "/v1/decisions/e1", "", "", ""); status != 401 {
			t.Fatalf("unauthenticated poll: HTTP %d", status)
		}
	})
	t.Run("approve/reject need only an Approver configured; auth is optional", func(t *testing.T) {
		// No Approver at all: still 503, regardless of auth or body.
		none := New(Config{})
		for _, p := range []string{"/v1/approvals/e1/reject", "/v1/approvals/e1"} {
			if status, _ := callJSON(t, none, http.MethodPost, p, skOps, "application/json", escBody(t, approval.Reject)); status != 503 {
				t.Fatalf("%s with no approver: HTTP %d, want 503", p, status)
			}
		}
		// Approver configured but no Authenticator (loopback dev, CS-151): the
		// signed envelope alone is enough; no credential is required at all.
		ap2 := &fakeApprover{}
		noAuth := New(Config{Approver: ap2})
		status, body := callJSON(t, noAuth, http.MethodPost, "/v1/approvals/e1/reject", "", "application/json", escBody(t, approval.Reject))
		if status != 403 || body["outcome"] != "deny" {
			t.Fatalf("reject without auth: HTTP %d %v", status, body)
		}
	})
	t.Run("poll still needs auth configured (unlike approve/reject)", func(t *testing.T) {
		g := New(Config{Approver: ap})
		if status, _ := callJSON(t, g, http.MethodGet, "/v1/decisions/e1", skOps, "", ""); status != 503 {
			t.Fatalf("poll: HTTP %d, want 503", status)
		}
	})
}

// TestApprovalEnvelopeFailures (CS-151): a malformed signed envelope never
// reaches the approver, a refused signature answers with the engine's deny
// (403, safe to act on), and GET /v1/approvals/{id} serves what to sign only
// for a pending escalation.
func TestApprovalEnvelopeFailures(t *testing.T) {
	good := escBody(t, approval.Approve)
	for _, path := range []string{"/v1/approvals/e1", "/v1/approvals/e1/reject"} {
		for _, c := range []struct {
			name, ctype, body string
			status            int
			code              Code
		}{
			{"wrong content type", "text/plain", good, 415, CodeUnsupportedMedia},
			{"empty body", "application/json", "", 400, CodeMalformedJSON},
			{"not JSON", "application/json", "{", 400, CodeMalformedJSON},
			{"duplicate key", "application/json", strings.Replace(good, `{"escalation_id"`, `{"kid":"x","escalation_id"`, 1), 400, CodeDuplicateKey},
			{"unknown field", "application/json", strings.Replace(good, `"kid"`, `"approver":"me","kid"`, 1), 400, CodeInvalidRequest},
			{"oversized", "application/json", strings.Replace(good, `"kid":"kid_ops"`, `"kid":"`+strings.Repeat("k", 5000)+`"`, 1), 413, CodeBodyTooLarge},
		} {
			t.Run(path+" "+c.name, func(t *testing.T) {
				ap := &fakeApprover{state: model.EscalationPending}
				g := New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}, Approver: ap})
				status, got := callJSON(t, g, http.MethodPost, path, skOps, c.ctype, c.body)
				if status != c.status || got["code"] != string(c.code) {
					t.Fatalf("HTTP %d %v, want %d %s", status, got, c.status, c.code)
				}
				if ap.sig.Kid != "" {
					t.Fatalf("a malformed envelope reached the approver: %+v", ap.sig)
				}
			})
		}
	}

	t.Run("a refused signature answers 403 with the engine's reason", func(t *testing.T) {
		ap := &fakeApprover{verdict: &model.Decision{RequestID: "e1", Outcome: model.Deny, Reasons: []model.Reason{{Code: "APPROVAL_SIG_PAYLOAD_MISMATCH"}}}}
		g := New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}, Approver: ap})
		status, got := callJSON(t, g, http.MethodPost, "/v1/approvals/e1", skOps, "application/json", good)
		reasons, _ := got["reasons"].([]any)
		if status != 403 || got["outcome"] != "deny" || len(reasons) != 1 || reasons[0].(map[string]any)["code"] != "APPROVAL_SIG_PAYLOAD_MISMATCH" {
			t.Fatalf("HTTP %d %v", status, got)
		}
	})

	ph := "sha256:" + strings.Repeat("b", 64)
	for _, c := range []struct {
		name, path, secret string
		state              model.EscalationState
		decision           *model.Decision
		err                error
		status             int
	}{
		{"pending: what to sign", "/v1/approvals/e1", skOps, model.EscalationPending, &model.Decision{PayloadHash: ph}, nil, 200},
		{"resolved: nothing to sign", "/v1/approvals/e1", skOps, model.EscalationAllowed, &model.Decision{PayloadHash: ph}, nil, 404},
		{"unknown id", "/v1/approvals/nope", skOps, model.EscalationPending, &model.Decision{PayloadHash: ph}, nil, 404},
		{"unauthenticated", "/v1/approvals/e1", "", model.EscalationPending, &model.Decision{PayloadHash: ph}, nil, 401},
		{"store down", "/v1/approvals/e1", skOps, model.EscalationPending, nil, errors.New("disk"), 500},
	} {
		t.Run("GET "+c.name, func(t *testing.T) {
			ap := &fakeApprover{state: c.state, decision: c.decision, err: c.err}
			g := New(Config{Authenticator: BearerAuthenticator{Store: lifecycleKeys(t)}, Approver: ap})
			status, got := callJSON(t, g, http.MethodGet, c.path, c.secret, "", "")
			if status != c.status {
				t.Fatalf("HTTP %d %v, want %d", status, got, c.status)
			}
			if status == 200 {
				maxExp, _ := got["max_expiry"].(float64)
				if got["escalation_id"] != "e1" || got["payload_hash"] != ph || got["tenant"] != "acme" ||
					int64(maxExp) > time.Now().Add(approval.MaxExpiryAhead).Unix()+1 {
					t.Fatalf("to-sign %v", got)
				}
			}
		})
	}
}
