package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

type fakeLimiter struct {
	mu                          sync.Mutex
	reserveErr                  error
	reserved, released, commits []string
}

func (l *fakeLimiter) Reserve(_ context.Context, id string, _ model.EnrichedRequest, _ time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reserveErr != nil {
		return l.reserveErr
	}
	l.reserved = append(l.reserved, id)
	return nil
}
func (l *fakeLimiter) Commit(_ context.Context, id, _ string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commits = append(l.commits, id)
	return nil
}
func (l *fakeLimiter) Release(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = append(l.released, id)
	return nil
}

type signFunc func(context.Context, model.Decision) (string, error)

func (f signFunc) Sign(ctx context.Context, d model.Decision) (string, error) { return f(ctx, d) }

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

func newRig() *rig {
	l, a := &fakeLimiter{}, &fakeAudit{}
	return &rig{limiter: l, audit: a, cfg: Config{
		Decoders: []Decoder{fakeDecoder{}}, Policy: outcome(model.Allow), Limiter: l,
		Signer: goodSigner, Audit: a, StageTimeout: 50 * time.Millisecond,
		Clock: func() time.Time { return time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC) },
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
		release bool // a reservation was made and must be released
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
		}, "", CodeSigner, true, true},
		{"signer empty token", func(r *rig) {
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { return "", nil })
		}, "", CodeSigner, true, true},
		{"signer panic", func(r *rig) {
			r.cfg.Signer = signFunc(func(context.Context, model.Decision) (string, error) { panic("boom") })
		}, "", CodeSigner, true, true},
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
	if err := e.Commit(context.Background(), "req-1", "0xabc"); err != nil {
		t.Fatal(err)
	}
	if err := e.Release(context.Background(), "req-2"); err != nil {
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
