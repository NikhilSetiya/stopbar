package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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

	"github.com/NikhilSetiya/stopbar/internal/approval"
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
	mu                                  sync.Mutex
	audit                               *fakeAudit
	reserveErr                          error
	reserved, released, commits, voided []string
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

// Void records which reservations were voided (Engine.Abandon).
func (l *fakeLimiter) Void(_ context.Context, id string, rec *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.voided = append(l.voided, id)
	return l.record(rec)
}

func (l *fakeLimiter) Owner(id string) (string, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return "test", "agent", slices.Contains(l.reserved, id)
}

type breakerFunc func(context.Context, string) (bool, error)

func (f breakerFunc) CircuitOpen(ctx context.Context, tenant string) (bool, error) {
	return f(ctx, tenant)
}

type signFunc func(context.Context, model.Decision) (string, error)

func (f signFunc) Sign(ctx context.Context, _ auth.Identity, _ model.ActionRequest, d model.Decision) (string, error) {
	return f(ctx, d)
}

// recordSigner records the requester identity each token was issued for.
type recordSigner struct{ ids []auth.Identity }

func (s *recordSigner) Sign(_ context.Context, id auth.Identity, _ model.ActionRequest, _ model.Decision) (string, error) {
	s.ids = append(s.ids, id)
	return "aGVhZA.cGF5bG9hZA.c2ln", nil
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
		// CS-124: an open breaker denies before decode, enrich or policy run.
		{"breaker open", func(r *rig) {
			r.cfg.Breaker = breakerFunc(func(_ context.Context, tenant string) (bool, error) { return tenant == "acme", nil })
			r.cfg.Decoders = []Decoder{noDecoder{}}
		}, "", CodeCircuitOpen, false, true},
		{"breaker store down", func(r *rig) {
			r.cfg.Breaker = breakerFunc(func(context.Context, string) (bool, error) { return false, errors.New("bolt: closed") })
		}, "", CodeLimiter, false, true},
		{"breaker panic", func(r *rig) {
			r.cfg.Breaker = breakerFunc(func(context.Context, string) (bool, error) { panic("boom") })
		}, "", CodeLimiter, false, true},
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

// withApprovers configures a quorum-of-1 approver set (CS-151) covering
// every named test approver below, so a single signed vote still decides
// the outcome the way a single approver string used to. The approve-
// lifecycle subtests (TestApprove, TestEscalationLifecycle) all use it.
func (r *rig) withApprovers() *rig {
	r.cfg.Approvers, r.cfg.ApprovalQuorum = approverKeySet, 1
	return r
}

// approver test keys (CS-151): one Ed25519 key per name used across the
// approval-lifecycle tests, tenant "acme" (the fixture's tenant),
// Owner.KeyID equal to the name so a self-approval test can bind an
// approver to a matching requester KeyID. Deterministic, so a failure is
// reproducible.
var (
	approverPrivs  = map[string]ed25519.PrivateKey{}
	approverKeySet *approval.KeySet
)

func init() {
	names := []string{"ops@example.com", "ak_ops", "ak_operator", "ak_requester", "ak_x"}
	keys := make([]approval.Key, 0, len(names))
	for _, name := range names {
		seed := sha256.Sum256([]byte("engine-test-approver:" + name))
		priv := ed25519.NewKeyFromSeed(seed[:])
		approverPrivs[name] = priv
		keys = append(keys, approval.Key{ID: name, Tenant: "acme", Owner: approval.Owner{KeyID: name}, Public: priv.Public().(ed25519.PublicKey)})
	}
	ks, err := approval.NewKeySet(keys)
	if err != nil {
		panic(err)
	}
	approverKeySet = ks
}

// approverKid is the kid a named test approver's signed envelope carries —
// what Decision.Approvals and PendingEscalation.ResolvedBy now hold,
// replacing the old approver-string identity.
func approverKid(t testing.TB, name string) string {
	t.Helper()
	priv, ok := approverPrivs[name]
	if !ok {
		t.Fatalf("no test approver key named %q", name)
	}
	return approval.Kid(priv.Public().(ed25519.PublicKey))
}

// signApprove/signReject build a signed escalation envelope for id/
// payloadHash from the named test approver key (rigNow + 1 minute: every
// rig in these tests runs on the fixed rigNow clock).
func signApprove(t testing.TB, name, id, payloadHash string) approval.SignedEscalation {
	return signEsc(t, name, id, payloadHash, approval.Approve)
}
func signReject(t testing.TB, name, id, payloadHash string) approval.SignedEscalation {
	return signEsc(t, name, id, payloadHash, approval.Reject)
}
func signEsc(t testing.TB, name, id, payloadHash, dec string) approval.SignedEscalation {
	t.Helper()
	priv, ok := approverPrivs[name]
	if !ok {
		t.Fatalf("no test approver key named %q", name)
	}
	s, err := approval.SignEscalation(priv, approval.EscalationObject{
		EscalationID: id, PayloadHash: payloadHash, Decision: dec, Expiry: rigNow.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// escFixturePayloadHash is the payload hash a manually-seeded
// PendingEscalation{Request: setID(fixtureRequest(...), id)} carries: with
// no .Decision set, PendingEscalation.payloadHash() falls back to exactly
// this (it depends only on Action fields, which setID never touches).
func escFixturePayloadHash(t testing.TB, id string) string {
	t.Helper()
	req := setID(fixtureRequest(t, "action_request.evm_tx.json"), id)
	ph, err := decision.PayloadHash(req.Action)
	if err != nil {
		t.Fatal(err)
	}
	return ph
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
		signer := &recordSigner{}
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		r.withApprovers()
		r.cfg.Signer = signer
		e := r.engine(t)

		req := fixtureRequest(t, "action_request.evm_tx.json")
		requester := auth.Identity{Method: auth.MethodAPIKey, Tenant: req.Tenant, AgentID: req.Actor.AgentID, KeyID: "ak_requester"}
		d, err := e.Evaluate(auth.WithIdentity(context.Background(), requester), req)
		if err != nil {
			t.Fatal(err)
		}
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
		approverCtx := auth.WithIdentity(context.Background(), auth.Identity{Method: auth.MethodAPIKey, Tenant: req.Tenant, KeyID: "ops@example.com"})
		ad, err := e.Approve(approverCtx, req.ID, signApprove(t, "ops@example.com", req.ID, d.PayloadHash))
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if ad.Outcome != model.Allow {
			t.Fatalf("approved Outcome = %v, want allow", ad.Outcome)
		}
		if ad.Token == "" {
			t.Fatal("approved allow has no signed token")
		}
		if len(ad.Approvals) != 1 || ad.Approvals[0].Approver != approverKid(t, "ops@example.com") {
			t.Fatalf("Approvals = %+v, want one from ops@example.com (kid %s)", ad.Approvals, approverKid(t, "ops@example.com"))
		}
		if !slices.Contains(r.limiter.reserved, req.ID) {
			t.Fatalf("approve did not reserve the cap; reserved=%v", r.limiter.reserved)
		}
		if got := pend.state(req.ID); got != model.EscalationAllowed {
			t.Fatalf("state after allow = %q, want allowed", got)
		}
		// decision-token v2: the token binds the requester, never the approver.
		if by := pend.m[req.ID].Requester; by.KeyID != requester.KeyID || len(signer.ids) != 1 || signer.ids[0].KeyID != requester.KeyID {
			t.Fatalf("token identity %+v, recorded requester %+v; want %s", signer.ids, by, requester.KeyID)
		}
		if got := r.audit.records[len(r.audit.records)-1]; got != model.AuditApproval {
			t.Fatalf("last audit record = %q, want approval (the resolution)", got)
		}
		if _, err := e.Approve(context.Background(), req.ID, signApprove(t, "ops@example.com", req.ID, d.PayloadHash)); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("second Approve err = %v, want ErrResolved", err)
		}
	})

	t.Run("approve is refused when a new rule now denies", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{escReason}, IssuedAt: rigNow}
		r := newRig()
		r.cfg.Policy = outcome(model.Deny) // state changed: it now denies
		r.withPending(pend)
		r.withApprovers()
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1")))
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
		r.withApprovers()
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1")))
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
		r.withApprovers()
		r.limiter.reserveErr = ErrCapExceeded // the cap filled while it waited
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1")))
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
		r.withApprovers()
		e := r.engine(t)

		before := len(r.audit.records)
		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1")))
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
		if _, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1"))); !errors.Is(err, model.ErrResolved) {
			t.Fatalf("Approve after expiry err = %v, want ErrResolved", err)
		}
	})

	t.Run("the requester may not approve their own escalation (cryptographic self-approval, CS-151)", func(t *testing.T) {
		pend := newFakePending()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
			Reasons: []string{escReason}, IssuedAt: rigNow, Requester: auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", KeyID: "ak_requester"}}
		r := newRig()
		r.cfg.Policy = outcome(model.Escalate)
		r.withPending(pend)
		r.withApprovers()
		e := r.engine(t)

		// The approver key bound to "ak_requester" is also the escalation's
		// requester → refused, record kept for a real approver.
		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_requester", "r1", escFixturePayloadHash(t, "r1")))
		if err != nil {
			t.Fatalf("Approve(self): %v", err)
		}
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalSelf {
			t.Fatalf("Outcome/reason = %v / %+v, want deny APPROVAL_SELF_APPROVAL", d.Outcome, d.Reasons)
		}
		if pend.len() != 1 {
			t.Fatalf("pending after self-approval = %d, want 1 (kept for another approver)", pend.len())
		}
		// a different approver key may still approve it.
		d2, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_operator", "r1", escFixturePayloadHash(t, "r1")))
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
		r.withApprovers()
		e := r.engine(t)

		d, err := e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", escFixturePayloadHash(t, "r1")))
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
		r.withApprovers()
		e := r.engine(t)
		if _, err := e.Approve(context.Background(), "nope", signApprove(t, "ops@example.com", "nope", "sha256:"+strings.Repeat("a", 64))); !errors.Is(err, model.ErrNoPending) {
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
		r.withApprovers()
		pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
			Reasons: []string{escReason}, IssuedAt: issued, Requester: auth.Identity{KeyID: requestedBy}, State: model.EscalationPending}
		return r, pend, r.engine(t)
	}
	bg := context.Background()

	t.Run("reject denies, is audited with the rejecting owner, and is final", func(t *testing.T) {
		r, pend, e := seed(t, rigNow, "ak_requester")
		ctx := auth.WithIdentity(bg, auth.Identity{Tenant: "acme", KeyID: "ak_ops"})
		d, err := e.Reject(ctx, "r1", signReject(t, "ak_ops", "r1", escFixturePayloadHash(t, "r1")))
		if err != nil {
			t.Fatal(err)
		}
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalReject {
			t.Fatalf("Reject = %v %+v, want deny APPROVAL_REJECTED", d.Outcome, d.Reasons)
		}
		wantKid := approverKid(t, "ak_ops")
		if pend.state("r1") != model.EscalationDenied || pend.m["r1"].ResolvedBy != wantKid {
			t.Fatalf("record = %+v, want denied by %s", pend.m["r1"], wantKid)
		}
		body := r.audit.bodies[len(r.audit.bodies)-1]
		veto, ok := body["veto"].(*approval.Vote)
		if !ok || veto.Kid != wantKid || body["identity"].(auth.Identity).KeyID != "ak_ops" {
			t.Fatalf("reject audit body lacks the rejecting owner: %+v", body)
		}
		if _, err := e.Approve(ctx, "r1", signApprove(t, "ak_ops", "r1", escFixturePayloadHash(t, "r1"))); !errors.Is(err, model.ErrResolved) {
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

	// CS-151 (spec/approval-signature-v1.md §7): self-approval is blocked,
	// but self-REJECT is explicitly allowed — rejecting your own escalation
	// only denies your own request, so there is nothing to gain by it. This
	// replaces the old API-key design's symmetric self-reject block.
	t.Run("the requester MAY reject their own escalation (self-approval only blocks approve)", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "ak_requester")
		d, err := e.Reject(bg, "r1", signReject(t, "ak_requester", "r1", escFixturePayloadHash(t, "r1")))
		if err != nil || d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeApprovalReject {
			t.Fatalf("self reject = %+v, %v; want deny APPROVAL_REJECTED", d, err)
		}
		if pend.state("r1") != model.EscalationDenied {
			t.Fatalf("state = %q, want denied", pend.state("r1"))
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
		if _, err := e.Reject(bg, "r1", signReject(t, "ak_ops", "r1", escFixturePayloadHash(t, "r1"))); !errors.Is(err, model.ErrResolved) {
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
		if _, err := e.Approve(other, "r1", signApprove(t, "ak_x", "r1", escFixturePayloadHash(t, "r1"))); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Approve err = %v", err)
		}
		if _, err := e.Reject(other, "r1", signReject(t, "ak_x", "r1", escFixturePayloadHash(t, "r1"))); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Reject err = %v", err)
		}
		if _, err := e.Status(other, "r1"); !errors.Is(err, ErrNoPending) {
			t.Fatalf("cross-tenant Status err = %v", err)
		}
	})

	t.Run("execute hook: a refused execution resolves as denied", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "")
		d, err := e.ApproveWith(bg, "r1", signApprove(t, "ak_ops", "r1", escFixturePayloadHash(t, "r1")), func(_ context.Context, d model.Decision, _ model.ActionRequest, _ auth.Identity) model.Decision {
			return e.denyWith(d, failed("FAIL_CLOSED_ADAPTER", errors.New("refused")))
		})
		if err != nil || d.Outcome != model.Deny || pend.state("r1") != model.EscalationDenied {
			t.Fatalf("ApproveWith = %v, %v, state %q; want deny / denied", d.Outcome, err, pend.state("r1"))
		}
	})

	t.Run("an allow whose resolution cannot be recorded fails closed", func(t *testing.T) {
		_, pend, e := seed(t, rigNow, "")
		e.cfg.Pending = &failingPut{pend}
		d, err := e.Approve(bg, "r1", signApprove(t, "ak_ops", "r1", escFixturePayloadHash(t, "r1")))
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

// TestApprovalSignatureFailures (CS-151): every way a signed approval can
// fail verification resolves nothing. Each comes back as a deny decision
// with an APPROVAL_SIG_* (or APPROVAL_SELF) reason, is audited as a refused
// attempt, reserves nothing, stores no vote, and leaves the escalation
// pending, so a valid vote can still approve it afterwards.
func TestApprovalSignatureFailures(t *testing.T) {
	const escReason = "taint-unknown-destination"
	ph := escFixturePayloadHash(t, "r1")
	resign := func(name string, f func(*approval.EscalationObject)) approval.SignedEscalation {
		o := approval.EscalationObject{EscalationID: "r1", PayloadHash: ph, Decision: approval.Approve, Expiry: rigNow.Add(time.Minute).Unix()}
		f(&o)
		s, err := approval.SignEscalation(approverPrivs[name], o)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	outsider := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	unknown, err := approval.SignEscalation(outsider, approval.EscalationObject{EscalationID: "r1", PayloadHash: ph, Decision: approval.Approve, Expiry: rigNow.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		sig    approval.SignedEscalation
		reject bool // post to Reject instead of Approve
		code   string
	}{
		{"payload hash of another transaction", resign("ak_ops", func(o *approval.EscalationObject) { o.PayloadHash = "sha256:" + strings.Repeat("0", 64) }), false, "APPROVAL_SIG_PAYLOAD_MISMATCH"},
		{"signed for another escalation (replay)", resign("ak_ops", func(o *approval.EscalationObject) { o.EscalationID = "r2" }), false, "APPROVAL_SIG_WRONG_ESCALATION_ID"},
		{"expired", resign("ak_ops", func(o *approval.EscalationObject) { o.Expiry = rigNow.Unix() }), false, "APPROVAL_SIG_EXPIRED"},
		{"expiry over an hour ahead", resign("ak_ops", func(o *approval.EscalationObject) { o.Expiry = rigNow.Add(2 * time.Hour).Unix() }), false, "APPROVAL_SIG_EXPIRY_TOO_FAR_AHEAD"},
		{"key not configured", unknown, false, "APPROVAL_SIG_UNKNOWN_KEY"},
		{"field changed under a valid signature", func() approval.SignedEscalation {
			s := signApprove(t, "ak_ops", "r1", ph)
			s.Expiry++
			return s
		}(), false, "APPROVAL_SIG_BAD_SIGNATURE"},
		{"signature not base64url", func() approval.SignedEscalation {
			s := signApprove(t, "ak_ops", "r1", ph)
			s.Sig = "!!"
			return s
		}(), false, "APPROVAL_SIG_MALFORMED"},
		{"reject envelope posted to approve", signReject(t, "ak_ops", "r1", ph), false, "APPROVAL_SIG_BAD_DECISION"},
		{"approve envelope posted to reject", signApprove(t, "ak_ops", "r1", ph), true, "APPROVAL_SIG_BAD_DECISION"},
		{"key bound to the requester", signApprove(t, "ak_requester", "r1", ph), false, CodeApprovalSelf},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pend := newFakePending()
			pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{escReason},
				IssuedAt: rigNow, State: model.EscalationPending, Requester: auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", KeyID: "ak_requester"}}
			r := newRig()
			r.cfg.Policy = outcome(model.Escalate)
			r.withPending(pend)
			r.withApprovers()
			e := r.engine(t)

			submit := e.Approve
			if tt.reject {
				submit = e.Reject
			}
			d, err := submit(context.Background(), "r1", tt.sig)
			if err != nil {
				t.Fatalf("err = %v, want a deny decision", err)
			}
			if d.Outcome != model.Deny || len(d.Reasons) != 1 || d.Reasons[0].Code != tt.code || d.Token != "" {
				t.Fatalf("decision %+v, want deny %s with no token", d, tt.code)
			}
			if got := r.audit.records; len(got) != 1 || got[0] != model.AuditDecision {
				t.Fatalf("audit records %v, want one refused-attempt decision", got)
			}
			if pend.state("r1") != model.EscalationPending || len(pend.m["r1"].Votes) != 0 || len(r.limiter.reserved) != 0 {
				t.Fatalf("refused signature changed state: %+v reserved=%v", pend.m["r1"], r.limiter.reserved)
			}
			if ad, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_ops", "r1", ph)); err != nil || ad.Outcome != model.Allow {
				t.Fatalf("a valid vote afterwards: %+v, %v", ad, err)
			}
		})
	}
}

// TestApprovalQuorum (CS-151): with a 2-of-N quorum one vote changes
// nothing but the recorded votes, the same owner cannot vote twice, a vote
// that cannot be recorded is not counted, and the second distinct owner's
// vote re-runs the pipeline and allows. With no approver keys nothing can be
// approved.
func TestApprovalQuorum(t *testing.T) {
	const escReason = "taint-unknown-destination"
	ph := escFixturePayloadHash(t, "r1")
	pend := newFakePending()
	pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"), Reasons: []string{escReason}, IssuedAt: rigNow, State: model.EscalationPending}
	r := newRig()
	r.cfg.Policy = outcome(model.Escalate)
	r.withPending(pend)
	r.cfg.Approvers, r.cfg.ApprovalQuorum = approverKeySet, 2
	e := r.engine(t)

	pend.err = errors.New("disk full")
	if _, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_ops", "r1", ph)); err == nil {
		t.Fatal("a vote that could not be recorded was accepted")
	}
	pend.err = nil
	if len(pend.m["r1"].Votes) != 0 {
		t.Fatalf("unrecorded vote counted: %+v", pend.m["r1"].Votes)
	}

	d, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_ops", "r1", ph))
	if err != nil || d.Outcome == model.Allow || len(pend.m["r1"].Votes) != 1 || pend.state("r1") != model.EscalationPending || len(r.limiter.reserved) != 0 {
		t.Fatalf("first of two votes: %+v, %v; votes %d reserved %v", d, err, len(pend.m["r1"].Votes), r.limiter.reserved)
	}
	if _, err := e.Approve(context.Background(), "r1", signApprove(t, "ak_ops", "r1", ph)); !errors.Is(err, approval.ErrDuplicateVote) {
		t.Fatalf("same owner again: err = %v, want ErrDuplicateVote", err)
	}
	d, err = e.Approve(context.Background(), "r1", signApprove(t, "ops@example.com", "r1", ph))
	if err != nil || d.Outcome != model.Allow || d.Token == "" || len(d.Approvals) != 2 || pend.state("r1") != model.EscalationAllowed {
		t.Fatalf("second distinct owner: %+v, %v", d, err)
	}

	r.cfg.Approvers = nil
	pend.m["r2"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r2"), Reasons: []string{escReason}, IssuedAt: rigNow}
	if _, err := r.engine(t).Approve(context.Background(), "r2", signApprove(t, "ak_ops", "r2", escFixturePayloadHash(t, "r2"))); err == nil {
		t.Fatal("approval with no approver keys configured succeeded")
	}
}
