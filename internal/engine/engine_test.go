package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

const bundle = "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

// ---- fakes ----

type fakeDecoder struct {
	fn func(context.Context, model.Action) (model.IntentSummary, error)
}

func (fakeDecoder) Supports(model.Action) bool { return true }
func (f fakeDecoder) Decode(ctx context.Context, a model.Action) (model.IntentSummary, error) {
	if f.fn != nil {
		return f.fn(ctx, a)
	}
	return model.IntentSummary{Kind: string(a.Kind), Human: "fake"}, nil
}

type noDecoder struct{}

func (noDecoder) Supports(model.Action) bool { return false }
func (noDecoder) Decode(context.Context, model.Action) (model.IntentSummary, error) {
	panic("must not be called")
}

type enrichFunc func(context.Context, *model.EnrichedRequest) error

func (f enrichFunc) Enrich(ctx context.Context, r *model.EnrichedRequest) error { return f(ctx, r) }

type policyFunc func(context.Context, model.EnrichedRequest) (PolicyResult, error)

func (f policyFunc) Evaluate(ctx context.Context, r model.EnrichedRequest) (PolicyResult, error) {
	return f(ctx, r)
}

func outcome(o model.Outcome) policyFunc {
	return func(context.Context, model.EnrichedRequest) (PolicyResult, error) {
		pr := PolicyResult{Outcome: o, BundleHash: bundle}
		if o != model.Allow {
			pr.Reasons = []model.Reason{{PolicyID: "taint-unknown-destination", Message: "m"}}
		}
		return pr, nil
	}
}

// fakeLimiter models the atomic store: an audit entry is written with the
// state change, and if the audit write fails, the change does not happen.
type fakeLimiter struct {
	mu                          sync.Mutex
	audit                       *fakeAudit
	reserveErr                  error
	reserved, released, commits []string
}

func (l *fakeLimiter) record(rec *model.AuditEntry) error {
	if rec == nil {
		return nil
	}
	if err := l.audit.Append(context.Background(), rec.Type, rec.Body); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

func (l *fakeLimiter) Reserve(_ context.Context, id string, _ model.EnrichedRequest, _ time.Duration, rec *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reserveErr != nil {
		return l.reserveErr
	}
	if err := l.record(rec); err != nil {
		return err
	}
	l.reserved = append(l.reserved, id)
	return nil
}
func (l *fakeLimiter) Commit(_ context.Context, id, _ string, rec *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.record(rec); err != nil {
		return err
	}
	l.commits = append(l.commits, id)
	return nil
}

// Release counts every attempt, but like the real limiter it writes nothing
// (no audit record) for an ID that holds no reservation.
func (l *fakeLimiter) Release(_ context.Context, id string, rec *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = append(l.released, id)
	if !slices.Contains(l.reserved, id) {
		return ErrUnknownReservation
	}
	return l.record(rec)
}

func (l *fakeLimiter) Owner(id string) (string, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return "test", "agent", slices.Contains(l.reserved, id)
}

type signFunc func(context.Context, model.Decision) (string, error)

func (f signFunc) Sign(ctx context.Context, _ model.ActionRequest, d model.Decision) (string, error) {
	return f(ctx, d)
}

var goodSigner = signFunc(func(context.Context, model.Decision) (string, error) { return "aGVhZA.cGF5bG9hZA.c2ln", nil })

type fakeAudit struct {
	mu      sync.Mutex
	err     error
	records []model.AuditRecordType
	bodies  []map[string]any
}

func (a *fakeAudit) Append(_ context.Context, typ model.AuditRecordType, body any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.records = append(a.records, typ)
	if m, ok := body.(map[string]any); ok {
		a.bodies = append(a.bodies, m)
	}
	return nil
}

type rig struct {
	cfg     Config
	limiter *fakeLimiter
	audit   *fakeAudit
}

// rigNow is the fixed clock the rig runs at, so tests that seed pending
// escalations can stamp IssuedAt to "now".
var rigNow = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func newRig() *rig {
	a := &fakeAudit{}
	l := &fakeLimiter{audit: a}
	return &rig{limiter: l, audit: a, cfg: Config{
		Decoders: []Decoder{fakeDecoder{}}, Policy: outcome(model.Allow), Limiter: l,
		Signer: goodSigner, Audit: a, StageTimeout: 50 * time.Millisecond,
		Clock: func() time.Time { return rigNow },
	}}
}

func (r *rig) engine(t testing.TB) *Engine {
	t.Helper()
	e, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func fixtureRequest(t testing.TB, name string) model.ActionRequest {
	t.Helper()
	b, err := os.ReadFile("../../spec/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r model.ActionRequest
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func evaluate(t testing.TB, e *Engine, req model.ActionRequest) model.Decision {
	t.Helper()
	d, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate returned an error: %v", err)
	}
	if verr := d.Validate(); verr != nil {
		t.Fatalf("invalid decision %+v: %v", d, verr)
	}
	if d.RequestID != req.ID {
		t.Fatalf("decision for %q, want %q", d.RequestID, req.ID)
	}
	return d
}

// ---- tests ----

func TestAllowPath(t *testing.T) {
	r := newRig()
	req := fixtureRequest(t, "action_request.evm_tx.json")
	d := evaluate(t, r.engine(t), req)
	want, _ := decision.PayloadHash(req.Action)
	switch {
	case d.Outcome != model.Allow:
		t.Fatalf("outcome %s, reasons %+v", d.Outcome, d.Reasons)
	case d.Token == "" || d.PayloadHash != want || d.PolicyBundleHash != bundle:
		t.Fatalf("allow not bound: %+v", d)
	case d.ReservationID == nil || *d.ReservationID != req.ID:
		t.Fatalf("reservation %v", d.ReservationID)
	case d.ExpiresAt.Sub(d.IssuedAt) != DefaultDecisionTTL:
		t.Fatalf("ttl %s", d.ExpiresAt.Sub(d.IssuedAt))
	case len(r.limiter.reserved) != 1 || len(r.limiter.released) != 0:
		t.Fatalf("limiter %+v", r.limiter)
	case len(r.audit.records) != 1 || r.audit.records[0] != model.AuditDecision:
		t.Fatalf("audit %+v", r.audit.records)
	}
	if _, ok := r.audit.bodies[0]["context"]; !ok {
		t.Error("allow audited without its policy context")
	}
}

func TestNonAllowOutcomesNeitherReserveNorSign(t *testing.T) {
	for _, o := range []model.Outcome{model.Deny, model.Escalate} {
		t.Run(string(o), func(t *testing.T) {
			r := newRig()
			r.cfg.Policy = outcome(o)
			signed := false
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { signed = true; return "x.y.z", nil })
			d := evaluate(t, r.engine(t), fixtureRequest(t, "action_request.evm_tx.json"))
			if d.Outcome != o || d.Token != "" || d.ReservationID != nil || signed || len(r.limiter.reserved) != 0 {
				t.Fatalf("got %+v (signed=%v, reserved=%v)", d, signed, r.limiter.reserved)
			}
			if d.Reasons[0].Code != CodePolicy || d.Reasons[0].PolicyID == "" {
				t.Fatalf("policy reason not coded: %+v", d.Reasons)
			}
			if len(r.audit.records) != 1 {
				t.Fatalf("audit %+v", r.audit.records)
			}
		})
	}
}

// TestFailClosed: every component failure mode ends in an audited deny with
// that stage's code, no token, and no reservation left behind.
func TestFailClosed(t *testing.T) {
	block := func(ctx context.Context) { <-make(chan struct{}) } // ignores ctx on purpose
	tests := []struct {
		name    string
		mutate  func(*rig)
		req     string
		code    string
		release bool // a release was attempted (after a reserve that may have landed)
		audited bool
	}{
		{"no payload binding (withdrawal)", nil, "withdrawal", CodeNormalize, false, true},
		{"no decoder supports the action", func(r *rig) { r.cfg.Decoders = []Decoder{noDecoder{}} }, "", CodeDecoder, false, true},
		{"decoder error", func(r *rig) {
			r.cfg.Decoders = []Decoder{fakeDecoder{fn: func(context.Context, model.Action) (model.IntentSummary, error) {
				return model.IntentSummary{}, errors.New("bad calldata")
			}}}
		}, "", CodeDecoder, false, true},
		{"decoder panic", func(r *rig) {
			r.cfg.Decoders = []Decoder{fakeDecoder{fn: func(context.Context, model.Action) (model.IntentSummary, error) { panic("boom") }}}
		}, "", CodeDecoder, false, true},
		{"decoder hangs", func(r *rig) {
			r.cfg.Decoders = []Decoder{fakeDecoder{fn: func(ctx context.Context, _ model.Action) (model.IntentSummary, error) {
				block(ctx)
				return model.IntentSummary{}, nil
			}}}
		}, "", CodeDecoder, false, true},
		{"decoder renders a different payload", func(r *rig) {
			r.cfg.Decoders = []Decoder{fakeDecoder{fn: func(context.Context, model.Action) (model.IntentSummary, error) {
				return model.IntentSummary{PayloadHash: "sha256:" + strings.Repeat("0", 64)}, nil
			}}}
		}, "", CodeDecoder, false, true},
		{"enricher error", func(r *rig) {
			r.cfg.Enrichers = []Enricher{enrichFunc(func(context.Context, *model.EnrichedRequest) error { return errors.New("rpc down") })}
		}, "", CodeEnrich, false, true},
		{"enricher hangs", func(r *rig) {
			r.cfg.Enrichers = []Enricher{enrichFunc(func(ctx context.Context, er *model.EnrichedRequest) error {
				block(ctx)
				return nil
			})}
		}, "", CodeEnrich, false, true},
		{"enricher removes taint", func(r *rig) {
			r.cfg.Enrichers = []Enricher{enrichFunc(func(_ context.Context, er *model.EnrichedRequest) error {
				er.Taint = nil
				return nil
			})}
		}, "", CodeEnrich, false, true},
		{"enricher rewrites destination", func(r *rig) {
			r.cfg.Enrichers = []Enricher{enrichFunc(func(_ context.Context, er *model.EnrichedRequest) error {
				er.Request.Action.To = "0x9f30000000000000000000000000000000000c21"
				return nil
			})}
		}, "", CodeEnrich, false, true},
		{"policy error", func(r *rig) {
			r.cfg.Policy = policyFunc(func(context.Context, model.EnrichedRequest) (PolicyResult, error) {
				return PolicyResult{}, errors.New("no active bundle")
			})
		}, "", CodePolicyFail, false, true},
		{"policy unknown outcome", func(r *rig) {
			r.cfg.Policy = policyFunc(func(context.Context, model.EnrichedRequest) (PolicyResult, error) {
				return PolicyResult{Outcome: "maybe", BundleHash: bundle}, nil
			})
		}, "", CodePolicyFail, false, true},
		{"policy deny without reasons", func(r *rig) {
			r.cfg.Policy = policyFunc(func(context.Context, model.EnrichedRequest) (PolicyResult, error) {
				return PolicyResult{Outcome: model.Deny, BundleHash: bundle}, nil
			})
		}, "", CodePolicyFail, false, true},
		{"policy allow without bundle hash", func(r *rig) {
			r.cfg.Policy = policyFunc(func(context.Context, model.EnrichedRequest) (PolicyResult, error) {
				return PolicyResult{Outcome: model.Allow}, nil
			})
		}, "", CodePolicyFail, false, true},
		{"cap exceeded", func(r *rig) { r.limiter.reserveErr = ErrCapExceeded }, "", CodeCapExceeded, true, true},
		{"circuit open", func(r *rig) { r.limiter.reserveErr = ErrCircuitOpen }, "", CodeCircuitOpen, true, true},
		{"limiter store down", func(r *rig) { r.limiter.reserveErr = errors.New("redis: connection refused") }, "", CodeLimiter, true, true},
		{"signer error", func(r *rig) {
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { return "", errors.New("kms throttled") })
		}, "", CodeSigner, false, true}, // signing happens before reserving: nothing to release
		{"signer empty token", func(r *rig) {
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { return "", nil })
		}, "", CodeSigner, false, true},
		{"signer panic", func(r *rig) {
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { panic("boom") })
		}, "", CodeSigner, false, true},
		// reserve + record are one write: with the audit down nothing was
		// reserved, and the engine still attempts the best-effort release
		{"audit down on allow", func(r *rig) { r.audit.err = errors.New("disk full") }, "", CodeAudit, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			if tt.mutate != nil {
				tt.mutate(r)
			}
			req := fixtureRequest(t, "action_request.evm_tx.json")
			if tt.req == "withdrawal" {
				req.Action = model.Action{Kind: model.KindWithdrawal, To: "acct-1"}
			}
			d := evaluate(t, r.engine(t), req)
			last := d.Reasons[len(d.Reasons)-1]
			if d.Outcome != model.Deny || d.Token != "" || last.Code != tt.code {
				t.Fatalf("got %s token=%q reasons=%+v, want deny %s", d.Outcome, d.Token, d.Reasons, tt.code)
			}
			if strings.Contains(last.Message, "redis") || strings.Contains(last.Message, "kms") || strings.Contains(last.Message, "boom") {
				t.Fatalf("internal error leaked into reason: %q", last.Message)
			}
			if got := len(r.limiter.released) > 0; got != tt.release {
				t.Fatalf("released=%v, want %v (reserved %v)", r.limiter.released, tt.release, r.limiter.reserved)
			}
			if got := len(r.audit.records) == 1; got != tt.audited {
				t.Fatalf("audit records %v, want audited=%v", r.audit.records, tt.audited)
			}
		})
	}
}

func TestAuditDownOnDenyKeepsReasons(t *testing.T) {
	r := newRig()
	r.cfg.Policy = outcome(model.Deny)
	r.audit.err = errors.New("disk full")
	d := evaluate(t, r.engine(t), fixtureRequest(t, "action_request.evm_tx.json"))
	if d.Outcome != model.Deny || len(d.Reasons) != 2 || d.Reasons[0].PolicyID != "taint-unknown-destination" || d.Reasons[1].Code != CodeAudit {
		t.Fatalf("got %+v", d.Reasons)
	}
}

func TestEnricherMayAddTaint(t *testing.T) {
	r := newRig()
	var seen []string
	r.cfg.Enrichers = []Enricher{enrichFunc(func(_ context.Context, er *model.EnrichedRequest) error {
		er.Taint = append(er.Taint, "fresh_deploy")
		return nil
	})}
	r.cfg.Policy = policyFunc(func(_ context.Context, er model.EnrichedRequest) (PolicyResult, error) {
		seen = er.Taint
		return outcome(model.Allow)(context.Background(), er)
	})
	if d := evaluate(t, r.engine(t), fixtureRequest(t, "action_request.evm_tx.json")); d.Outcome != model.Allow {
		t.Fatalf("got %+v", d)
	}
	if strings.Join(seen, ",") != "untrusted_onchain,decoded,fresh_deploy" {
		t.Fatalf("policy saw taint %v", seen)
	}
}

func TestNewRequiresComponents(t *testing.T) {
	if _, err := New(Config{}); err == nil || !strings.Contains(err.Error(), "[Audit Decoders Limiter Policy Signer]") {
		t.Fatalf("err = %v", err)
	}
	r := newRig()
	r.cfg.DecisionTTL = model.MaxTTL + time.Second
	if _, err := New(r.cfg); err == nil {
		t.Fatal("DecisionTTL above MaxTTL accepted")
	}
}

func TestCommitAndReleaseAreAudited(t *testing.T) {
	r := newRig()
	e := r.engine(t)
	r.limiter.reserved = []string{"req-1", "req-2", "req-3"}
	if err := e.Commit(context.Background(), "req-1", "0xabc"); err != nil {
		t.Fatal(err)
	}
	if err := e.Release(context.Background(), "req-2", "client"); err != nil {
		t.Fatal(err)
	}
	if strings.Join([]string{string(r.audit.records[0]), string(r.audit.records[1])}, ",") != "commit,release" {
		t.Fatalf("records %v", r.audit.records)
	}
	r.audit.err = errors.New("disk full")
	if err := e.Commit(context.Background(), "req-3", "0xdef"); err == nil {
		t.Fatal("unaudited commit reported success")
	}
}

func TestConcurrentEvaluations(t *testing.T) {
	r := newRig()
	e := r.engine(t)
	req := fixtureRequest(t, "action_request.evm_tx.json")
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, _ := e.Evaluate(context.Background(), req); d.Outcome != model.Allow {
				t.Errorf("got %s", d.Outcome)
			}
		}()
	}
	wg.Wait()
	if len(r.limiter.reserved) != 64 || len(r.audit.records) != 64 {
		t.Fatalf("reserved %d, audited %d", len(r.limiter.reserved), len(r.audit.records))
	}
}

// TestThroughGateway wires the real gateway to the engine: the status code
// alone tells a client what it may do.
func TestThroughGateway(t *testing.T) {
	body, err := os.ReadFile("../../spec/fixtures/action_request.evm_tx.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*rig)
		status int
		token  bool
	}{
		{"allow", nil, 200, true},
		{"escalate", func(r *rig) { r.cfg.Policy = outcome(model.Escalate) }, 202, false},
		{"policy deny", func(r *rig) { r.cfg.Policy = outcome(model.Deny) }, 403, false},
		{"fail closed", func(r *rig) { r.limiter.reserveErr = ErrCapExceeded }, 403, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig()
			if tt.mutate != nil {
				tt.mutate(r)
			}
			fixtureNow := func() time.Time { return time.Date(2026, 11, 2, 10, 0, 10, 0, time.UTC) }
			srv := httptest.NewServer(gateway.New(gateway.Config{Evaluator: r.engine(t), Clock: fixtureNow}))
			defer srv.Close()
			res, err := http.Post(srv.URL+"/v1/evaluate", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			var d model.Decision
			if res.StatusCode != tt.status || json.Unmarshal(b, &d) != nil || (d.Token != "") != tt.token {
				t.Fatalf("status %d body %s", res.StatusCode, b)
			}
		})
	}
}

// Denials that cannot be audited are counted and logged, never silent.
func TestUnauditedDenialsAreCounted(t *testing.T) {
	r := newRig()
	r.audit.err = errors.New("disk full")
	for _, o := range []model.Outcome{model.Allow, model.Deny} {
		r.cfg.Policy = outcome(o)
		e := r.engine(t)
		d := evaluate(t, e, fixtureRequest(t, "action_request.evm_tx.json"))
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeAudit {
			t.Fatalf("%s with audit down: %+v", o, d.Reasons)
		}
		if got := e.Counters()["stopbar_audit_unavailable_denials_total"]; got == 0 {
			t.Fatalf("%s: unaudited denial not counted", o)
		}
	}
}

// fakePending is an in-memory PendingStore for the approval-lifecycle tests.
type fakePending struct {
	mu    sync.Mutex
	m     map[string]PendingEscalation
	err   error      // forced on every call when set
	audit *fakeAudit // Put writes its audit record here, atomically
}

func newFakePending() *fakePending { return &fakePending{m: map[string]PendingEscalation{}} }

// Put models the store's single transaction: if the audit record cannot be
// written, the state change does not happen either.
func (p *fakePending) Put(_ context.Context, e PendingEscalation, rec *model.AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if rec != nil && p.audit != nil {
		if err := p.audit.Append(context.Background(), rec.Type, rec.Body); err != nil {
			return err
		}
	}
	p.m[e.Request.ID] = e
	return nil
}
func (p *fakePending) Get(_ context.Context, id string) (PendingEscalation, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return PendingEscalation{}, false, p.err
	}
	e, ok := p.m[id]
	return e, ok, nil
}
func (p *fakePending) len() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.m) }
func (p *fakePending) state(id string) model.EscalationState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[id].State
}

func (r *rig) withPending(p *fakePending) *fakePending {
	p.audit = r.audit
	r.cfg.Pending = p
	return p
}

// TestApprove covers the escalation lifecycle (CS-151/152): an escalation is
// recorded, approving it re-runs enrich/policy/limiter against current state,
// and approval is refused if a new rule denies, a new escalation appears, a cap
// has filled, the pending window has expired, or the requester tries to approve
// their own escalation. Approval ignores the request's own freshness TTL.
func TestApprove(t *testing.T) {
	const escReason = "taint-unknown-destination" // what outcome(Escalate) emits

	t.Run("escalate records a pending entry; approve promotes to allow and signs", func(t *testing.T) {
		r := newRig()
		pend := newFakePending()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		e := r.engine(t)

		req := fixtureRequest(t, "action_request.evm_tx.json")
		d := evaluate(t, e, req)
		if d.Outcome != model.Escalate {
			t.Fatalf("Outcome = %v, want escalate", d.Outcome)
		}
		if pend.len() != 1 {
			t.Fatalf("pending entries = %d, want 1", pend.len())
		}
		if got := len(r.limiter.reserved); got != 0 {
			t.Fatalf("escalation reserved %d caps, want 0", got)
		}

		// A human approves: the single escalation reason is now waived.
		ad, err := e.Approve(context.Background(), req.ID, "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if ad.Outcome != model.Allow {
			t.Fatalf("approved Outcome = %v, want allow", ad.Outcome)
		}
		if ad.Token == "" {
			t.Fatal("approved allow has no signed token")
		}
		if len(ad.Approvals) != 1 || ad.Approvals[0].Approver != "ops@example.com" {
			t.Fatalf("Approvals = %+v, want one from ops@example.com", ad.Approvals)
		}
		if !slices.Contains(r.limiter.reserved, req.ID) {
			t.Fatalf("approve did not reserve the cap; reserved=%v", r.limiter.reserved)
		}
		if got := pend.state(req.ID); got != model.EscalationAllowed {
			t.Fatalf("state after allow = %q, want allowed", got)
		}
		if got := r.audit.records[len(r.audit.records)-1]; got != model.AuditApproval {
			t.Fatalf("last audit record = %q, want approval (the resolution)", got)
		}
		if _, err := e.Approve(context.Background(), req.ID, "ops@example.com"); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("second Approve err = %v, want ErrResolved", err)
		}
	})

	t.Run("approve is refused when a new rule now denies", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{escReason}, IssuedAt: rigNow}
		r := newRig()
		r.cfg.Policy = outcome(model.Deny) // state changed: it now denies
		r.withPending(pend)
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if d.Outcome != model.Deny {
			t.Fatalf("Outcome = %v, want deny", d.Outcome)
		}
		if len(r.limiter.reserved) != 0 {
			t.Fatalf("a denied approval reserved %d caps, want 0", len(r.limiter.reserved))
		}
		if pend.len() != 1 {
			t.Fatalf("pending entries after refusal = %d, want 1 (kept)", pend.len())
		}
	})

	t.Run("approve is refused when a new escalation reason appears", func(t *testing.T) {
		// The recorded escalation covered one reason; re-running produces a
		// different reason the approver never saw, so it must not auto-allow.
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{"some-old-reason"}, IssuedAt: rigNow}
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate) // emits escReason, which is NOT approved
		r.withPending(pend)
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if d.Outcome != model.Escalate {
			t.Fatalf("Outcome = %v, want escalate (unapproved reason)", d.Outcome)
		}
		if len(r.limiter.reserved) != 0 {
			t.Fatalf("reserved %d caps on a still-escalated request, want 0", len(r.limiter.reserved))
		}
	})

	t.Run("approve is refused when the cap has since filled", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{escReason}, IssuedAt: rigNow}
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		r.limiter.reserveErr = ErrCapExceeded // the cap filled while it waited
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if d.Outcome != model.Deny {
			t.Fatalf("Outcome = %v, want deny (cap full)", d.Outcome)
		}
		if pend.len() != 1 {
			t.Fatalf("pending entries after cap-full refusal = %d, want 1 (kept)", pend.len())
		}
	})

	t.Run("approval after the pending window expires is refused, audited and resolved as expired", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
			Reasons: []string{escReason}, IssuedAt: rigNow.Add(-16 * time.Minute)} // past the 15m default
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate) // would otherwise promote to allow
		r.withPending(pend)
		e := r.engine(t)

		before := len(r.audit.records)
		d, err := e.Approve(context.Background(), "r1", "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalExpired {
			t.Fatalf("Outcome/reason = %v / %+v, want deny APPROVAL_EXPIRED", d.Outcome, d.Reasons)
		}
		if len(r.audit.records) != before+1 {
			t.Fatalf("expired refusal wrote %d audit records, want 1", len(r.audit.records)-before)
		}
		if len(r.limiter.reserved) != 0 {
			t.Fatalf("an expired approval reserved %d caps, want 0", len(r.limiter.reserved))
		}
		if got := pend.state("r1"); got != model.EscalationExpired {
			t.Fatalf("state = %q, want expired", got)
		}
		if _, err := e.Approve(context.Background(), "r1", "ops@example.com"); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("Approve after expiry err = %v, want ErrResolved", err)
		}
	})

	t.Run("the requester may not approve their own escalation", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
			Reasons: []string{escReason}, IssuedAt: rigNow, RequestedBy: "ak_requester"}
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		e := r.engine(t)

		// same identity as the requester → refused, record kept for a real approver.
		d, err := e.Approve(context.Background(), "r1", "ak_requester")
		if err != nil {
			t.Fatalf("Approve(self): %v", err)
		}
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalSelf {
			t.Fatalf("Outcome/reason = %v / %+v, want deny APPROVAL_SELF_APPROVAL", d.Outcome, d.Reasons)
		}
		if pend.len() != 1 {
			t.Fatalf("pending after self-approval = %d, want 1 (kept for another approver)", pend.len())
		}
		// a different identity may still approve it.
		d2, err := e.Approve(context.Background(), "r1", "ak_operator")
		if err != nil {
			t.Fatalf("Approve(operator): %v", err)
		}
		if d2.Outcome != model.Allow {
			t.Fatalf("a different approver got %v, want allow", d2.Outcome)
		}
	})

	t.Run("approval ignores the request's own freshness TTL", func(t *testing.T) {
		// The original request TTL (≤5m, checked at the gateway) may well have
		// passed by the time a human approves; within the pending window the
		// approval must still go through. Guards against a freshness check
		// creeping into the engine's approval path.
		stale := setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1")
		stale.IssuedAt = rigNow.Add(-10 * time.Minute) // long past its ttl_seconds
		stale.TTLSeconds = 60
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: stale, Reasons: []string{escReason}, IssuedAt: rigNow}
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", "ops@example.com")
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if d.Outcome != model.Allow {
			t.Fatalf("Outcome = %v, want allow (request TTL must not block approval)", d.Outcome)
		}
	})

	t.Run("unknown id is ErrNoPending", func(t *testing.T) {
		r := newRig()
		r.withPending(newFakePending())
		e := r.engine(t)
		if _, err := e.Approve(context.Background(), "nope", "ops@example.com"); !errors.Is(err, model.ErrNoPending) {
			t.Fatalf("Approve(unknown) err = %v, want ErrNoPending", err)
		}
	})
}

func setID(req model.ActionRequest, id string) model.ActionRequest {
	req.ID = id
	return req
}

// TestEscalationLifecycle covers CS-152 beyond approve: reject → deny,
// timeout → deny surfaced by polling, the requester cannot reject either,
// approvers only see their own tenant, the gatekeeper's execute hook decides
// the final state, and every state change is audited in the same write.
func TestEscalationLifecycle(t *testing.T) {
	const escReason = "taint-unknown-destination"
	seed := func(t *testing.T, issued time.Time, requestedBy string) (*rig, *fakePending, *Engine) {
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		pend := r.withPending(newFakePending())
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
			Reasons: []string{escReason}, IssuedAt: issued, RequestedBy: requestedBy, State: model.EscalationPending}
		return r, pend, r.engine(t)
	}
	bg := context.Background()

	t.Run("reject denies, is audited with the approver, and is final", func(t *testing.T) {
		r, pend, e := seed(t, rigNow, "ak_requester")
		ctx := auth.WithIdentity(bg, auth.Identity{Tenant: "acme", KeyID: "ak_ops"})
		d, err := e.Reject(ctx, "r1", "ak_ops")
		if err != nil {
			t.Fatal(err)
		}
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalReject {
			t.Fatalf("Reject = %v %+v, want deny APPROVAL_REJECTED", d.Outcome, d.Reasons)
		}
		if pend.state("r1") != model.EscalationDenied || pend.m["r1"].ResolvedBy != "ak_ops" {
			t.Fatalf("record = %+v, want denied by ak_ops", pend.m["r1"])
		}
		body := r.audit.bodies[len(r.audit.bodies)-1]
		if body["approver"] != "ak_ops" || body["identity"].(auth.Identity).KeyID != "ak_ops" {
			t.Fatalf("reject audit body lacks the approver identity: %+v", body)
		}
		if _, err := e.Approve(ctx, "r1", "ak_ops"); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("Approve after reject err = %v, want ErrResolved", err)
		}
		if len(r.limiter.reserved) != 0 {
			t.Fatal("a rejected escalation reserved caps")
		}
		st, err := e.Status(ctx, "r1")
		if err != nil || st.State != model.EscalationDenied || st.Decision == nil || st.Decision.Outcome != model.Deny {
			t.Fatalf("Status = %+v, %v; want denied with the deny decision", st, err)
		}
	})

	t.Run("the requester may not reject their own escalation", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "ak_requester")
		d, err := e.Reject(bg, "r1", "ak_requester")
		if err != nil || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalSelf {
			t.Fatalf("self Reject = %+v, %v; want APPROVAL_SELF_APPROVAL", d, err)
		}
		if pend.state("r1") != model.EscalationPending {
			t.Fatalf("state = %q, want still pending", pend.state("r1"))
		}
	})

	t.Run("polling after the window resolves it as expired, audited once", func(t *testing.T) {
		r, pend, e := seed(t, rigNow.Add(-DefaultPendingTTL-time.Second), "")
		st, err := e.Status(bg, "r1")
		if err != nil {
			t.Fatal(err)
		}
		if st.State != model.EscalationExpired || st.Decision.Reasons[len(st.Decision.Reasons)-1].Code != CodeApprovalExpired {
			t.Fatalf("Status = %+v, want expired with APPROVAL_EXPIRED", st)
		}
		if !st.ExpiresAt.Equal(pend.m["r1"].IssuedAt.Add(DefaultPendingTTL)) {
			t.Fatalf("ExpiresAt = %v", st.ExpiresAt)
		}
		n := len(r.audit.records)
		if _, err := e.Status(bg, "r1"); err != nil || len(r.audit.records) != n {
			t.Fatalf("a second poll wrote %d more audit records (err %v), want 0", len(r.audit.records)-n, err)
		}
		if _, err := e.Reject(bg, "r1", "ak_ops"); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("Reject after expiry err = %v, want ErrResolved", err)
		}
	})

	t.Run("an expiry that cannot be audited does not happen", func(t *testing.T) {
		r, pend, e := seed(t, rigNow.Add(-DefaultPendingTTL-time.Second), "")
		r.audit.err = errors.New("disk full")
		if _, err := e.Status(bg, "r1"); err == nil {
			t.Fatal("Status succeeded with the audit log down")
		}
		if pend.state("r1") != model.EscalationPending {
			t.Fatalf("state = %q, want pending (unaudited change must not happen)", pend.state("r1"))
		}
	})

	t.Run("another tenant's approver cannot see or resolve it", func(t *testing.T) {
		_, _, e := seed(t, rigNow, "")
		other := auth.WithIdentity(bg, auth.Identity{Tenant: "other", KeyID: "ak_x"})
		if _, err := e.Approve(other, "r1", "ak_x"); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Approve err = %v", err)
		}
		if _, err := e.Reject(other, "r1", "ak_x"); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Reject err = %v", err)
		}
		if _, err := e.Status(other, "r1"); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Status err = %v", err)
		}
	})

	t.Run("execute hook: a refused execution resolves as denied", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "")
		d, err := e.ApproveWith(bg, "r1", "ak_ops", func(_ context.Context, d model.Decision, _ model.ActionRequest) model.Decision {
			return e.denyWith(d, failed("FAIL_CLOSED_ADAPTER", errors.New("refused")))
		})
		if err != nil || d.Outcome != model.Deny || pend.state("r1") != model.EscalationDenied {
			t.Fatalf("ApproveWith = %v, %v, state %q; want deny / denied", d.Outcome, err, pend.state("r1"))
		}
	})

	t.Run("an allow whose resolution cannot be recorded fails closed", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "")
		e.cfg.Pending = &failingPut{pend}
		d, err := e.Approve(bg, "r1", "ak_ops")
		if err != nil || d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeAudit || d.Token != "" {
			t.Fatalf("Approve = %+v, %v; want deny FAIL_CLOSED_AUDIT without a token", d, err)
		}
	})

	t.Run("an escalation that cannot be recorded is a deny", func(t *testing.T) {
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(newFakePending()).err = errors.New("disk full")
		d := evaluate(t, r.engine(t), fixtureRequest(t, "action_request.evm_tx.json"))
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeAudit {
			t.Fatalf("Outcome = %v %+v, want deny FAIL_CLOSED_AUDIT", d.Outcome, d.Reasons)
		}
	})
}

// failingPut lets Get through but fails every Put.
type failingPut struct{ *fakePending }

func (f *failingPut) Put(context.Context, PendingEscalation, *model.AuditEntry) error {
	return errors.New("disk full")
}

func TestCommitReleaseCarryIdentityAndDomainErrors(t *testing.T) {
	r := newRig()
	e := r.engine(t)
	r.limiter.reserved = []string{"req-1"}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Tenant: "test", AgentID: "agent", KeyID: "ak_agent"})
	if err := e.Commit(ctx, "req-1", "0xabc"); err != nil {
		t.Fatal(err)
	}
	if id, ok := r.audit.bodies[0]["identity"].(auth.Identity); !ok || id.KeyID != "ak_agent" {
		t.Fatalf("commit audit body lacks identity: %+v", r.audit.bodies[0])
	}
	if err := e.Release(ctx, "nope", "client"); !errors.Is(err, ErrUnknownReservation) {
		t.Fatalf("Release(unknown) = %v, want it to unwrap to ErrUnknownReservation", err)
	}
	if tenant, agent, ok := e.Owner("req-1"); !ok || tenant != "test" || agent != "agent" {
		t.Fatalf("Owner = %q %q %v", tenant, agent, ok)
	}
}
