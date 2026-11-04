package gateway

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// fixtureTime is just after the fixtures' issued_at, so they are fresh.
var fixtureTime = time.Date(2026, 11, 2, 10, 0, 10, 0, time.UTC)

// newGW builds a gateway whose clock is pinned to the fixtures (tests only;
// stopbard has no clock setting).
func newGW(cfg Config) *Gateway {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return fixtureTime }
	}
	return New(cfg)
}

// alwaysFresh lets the fuzzer reach the evaluator with repeated nonces.
type alwaysFresh struct{}

func (alwaysFresh) Consume(string, time.Time) (bool, error) { return true, nil }

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../spec/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// evalFunc adapts a function to Evaluator.
type evalFunc func(context.Context, model.ActionRequest) (model.Decision, error)

func (f evalFunc) Evaluate(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
	return f(ctx, r)
}

func decide(o model.Outcome) evalFunc {
	return func(_ context.Context, r model.ActionRequest) (model.Decision, error) {
		now := time.Now()
		d := model.Decision{RequestID: r.ID, Outcome: o, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		if o == model.Allow {
			d.PolicyBundleHash = "sha256:" + strings.Repeat("a", 64)
			d.PayloadHash = "sha256:" + strings.Repeat("b", 64)
		} else {
			d.Reasons = []model.Reason{{PolicyID: "p", Message: "m"}}
		}
		return d, nil
	}
}

func do(t testing.TB, h http.Handler, method, path, ctype string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func errCode(t testing.TB, b []byte) Code {
	t.Helper()
	var e ErrorBody
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body not JSON: %q", b)
	}
	return e.Code
}

// mutate rewrites the evm fixture through a JSON round trip.
func mutate(t testing.TB, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixture(t, "action_request.evm_tx.json"), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEvaluateRejects(t *testing.T) {
	evm := fixture(t, "action_request.evm_tx.json")
	g := newGW(Config{Evaluator: decide(model.Allow)})
	tests := []struct {
		name   string
		method string
		path   string
		ctype  string
		body   []byte
		status int
		code   Code
	}{
		{"unknown route", "GET", "/v1/nope", "", nil, 404, CodeNotFound},
		{"GET evaluate", "GET", "/v1/evaluate", "", nil, 405, CodeMethodNotAllowed},
		{"POST healthz", "POST", "/healthz", "application/json", nil, 405, CodeMethodNotAllowed},
		{"no content type", "POST", "/v1/evaluate", "", evm, 415, CodeUnsupportedMedia},
		{"text/plain", "POST", "/v1/evaluate", "text/plain", evm, 415, CodeUnsupportedMedia},
		{"too large", "POST", "/v1/evaluate", "application/json", bytes.Repeat([]byte(" "), MaxBodyBytes+1), 413, CodeBodyTooLarge},
		{"empty body", "POST", "/v1/evaluate", "application/json", nil, 400, CodeMalformedJSON},
		{"not json", "POST", "/v1/evaluate", "application/json", []byte("{"), 400, CodeMalformedJSON},
		{"invalid utf-8", "POST", "/v1/evaluate", "application/json", []byte("{\"id\":\"\xff\"}"), 400, CodeMalformedJSON},
		{"trailing data", "POST", "/v1/evaluate", "application/json", append(append([]byte{}, evm...), []byte("{}")...), 400, CodeMalformedJSON},
		{"duplicate key", "POST", "/v1/evaluate", "application/json", []byte(`{"id":"a","id":"b"}`), 400, CodeDuplicateKey},
		{"case-variant duplicate", "POST", "/v1/evaluate", "application/json", bytes.Replace(evm, []byte(`"to":`), []byte(`"To":"0x9f30000000000000000000000000000000000c21","to":`), 1), 400, CodeUnknownField},
		{"case-variant field", "POST", "/v1/evaluate", "application/json", bytes.Replace(evm, []byte(`"tenant":`), []byte(`"Tenant":`), 1), 400, CodeUnknownField},
		{"unknown top-level field", "POST", "/v1/evaluate", "application/json", mutate(t, func(m map[string]any) { m["admin"] = true }), 400, CodeUnknownField},
		{"unknown nested field", "POST", "/v1/evaluate", "application/json", mutate(t, func(m map[string]any) { m["action"].(map[string]any)["gas"] = "1" }), 400, CodeUnknownField},
		{"int above 2^53", "POST", "/v1/evaluate", "application/json", bytes.Replace(evm, []byte(`"chain_id": 8453`), []byte(`"chain_id": 9007199254740993`), 1), 400, CodeNumberPrecision},
		{"exponent int above 2^53", "POST", "/v1/evaluate", "application/json", bytes.Replace(evm, []byte(`"ttl_seconds": 60`), []byte(`"ttl_seconds": 1e20`), 1), 400, CodeNumberPrecision},
		{"wrong type", "POST", "/v1/evaluate", "application/json", bytes.Replace(evm, []byte(`"ttl_seconds": 60`), []byte(`"ttl_seconds": "60"`), 1), 400, CodeInvalidRequest},
		{"array body", "POST", "/v1/evaluate", "application/json", []byte(`[]`), 400, CodeInvalidRequest},
		{"null body", "POST", "/v1/evaluate", "application/json", []byte(`null`), 400, CodeInvalidRequest},
		{"fails validation", "POST", "/v1/evaluate", "application/json", mutate(t, func(m map[string]any) { m["action"].(map[string]any)["value_wei"] = "-1" }), 400, CodeInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, b := do(t, g, tt.method, tt.path, tt.ctype, tt.body)
			if res.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d (body %s)", res.StatusCode, tt.status, b)
			}
			if got := errCode(t, b); got != tt.code {
				t.Fatalf("code = %s, want %s (body %s)", got, tt.code, b)
			}
			if ct := res.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q", ct)
			}
		})
	}
}

func TestValidationReportsAllProblems(t *testing.T) {
	g := newGW(Config{Evaluator: decide(model.Allow)})
	_, b := do(t, g, "POST", "/v1/evaluate", "application/json", []byte(`{"id":"r1","action":{"kind":"evm_tx"}}`))
	var e ErrorBody
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != CodeInvalidRequest || e.RequestID != "r1" || len(e.Problems) < 5 {
		t.Fatalf("got %+v", e)
	}
}

func TestEvaluateOutcomes(t *testing.T) {
	for _, tt := range []struct {
		fixture string
		outcome model.Outcome
		status  int
	}{
		{"action_request.evm_tx.json", model.Allow, 200},
		{"action_request.evm_tx.json", model.Deny, 403},
		{"action_request.evm_tx.json", model.Escalate, 202},
		{"action_request.tool_call.json", model.Deny, 403},
		{"action_request.tool_call.json", model.Allow, 200},
	} {
		t.Run(tt.fixture+"/"+string(tt.outcome), func(t *testing.T) {
			g := newGW(Config{Evaluator: decide(tt.outcome)})
			res, b := do(t, g, "POST", "/v1/evaluate", "application/json; charset=utf-8", fixture(t, tt.fixture))
			if res.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d (%s)", res.StatusCode, tt.status, b)
			}
			var d model.Decision
			if err := json.Unmarshal(b, &d); err != nil || d.Outcome != tt.outcome || d.Validate() != nil {
				t.Fatalf("bad decision %s (%v)", b, err)
			}
		})
	}
}

// TestFailClosed: nothing that goes wrong behind the gateway may surface as a
// 2xx, and the server must survive it.
func TestFailClosed(t *testing.T) {
	evm := fixture(t, "action_request.evm_tx.json")
	tests := []struct {
		name   string
		eval   Evaluator
		status int
		code   Code
	}{
		{"no engine", nil, 503, CodeEngineUnavailable},
		{"engine error", evalFunc(func(context.Context, model.ActionRequest) (model.Decision, error) {
			return model.Decision{}, errors.New("boom")
		}), 500, CodeInternal},
		{"engine panic", evalFunc(func(context.Context, model.ActionRequest) (model.Decision, error) {
			panic("boom")
		}), 500, CodeInternal},
		{"invalid decision (allow without binding)", evalFunc(func(_ context.Context, r model.ActionRequest) (model.Decision, error) {
			now := time.Now()
			return model.Decision{RequestID: r.ID, Outcome: model.Allow, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
		}), 500, CodeInternal},
		{"decision for another request", evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
			r.ID = "someone-else"
			return decide(model.Allow)(ctx, r)
		}), 500, CodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGW(Config{Evaluator: tt.eval})
			res, b := do(t, g, "POST", "/v1/evaluate", "application/json", evm)
			if res.StatusCode != tt.status || errCode(t, b) != tt.code {
				t.Fatalf("got %d %s, want %d %s", res.StatusCode, b, tt.status, tt.code)
			}
			if res, _ := do(t, g, "GET", "/healthz", "", nil); res.StatusCode != 200 {
				t.Fatalf("healthz after failure = %d", res.StatusCode)
			}
		})
	}
}

func TestHealthzAndMetrics(t *testing.T) {
	g := newGW(Config{Evaluator: decide(model.Deny)})
	if res, b := do(t, g, "GET", "/healthz", "", nil); res.StatusCode != 200 || !bytes.Contains(b, []byte(`"ok"`)) {
		t.Fatalf("healthz: %d %s", res.StatusCode, b)
	}
	if res, _ := do(t, g, "POST", "/v1/evaluate", "application/json", fixture(t, "action_request.evm_tx.json")); res.StatusCode != 403 {
		t.Fatalf("deny status = %d", res.StatusCode)
	}
	do(t, g, "POST", "/v1/evaluate", "application/json", []byte("{"))
	do(t, g, "GET", "/v1/attacker-controlled-path-1", "", nil)
	do(t, g, "GET", "/v1/attacker-controlled-path-2", "", nil)
	res, b := do(t, g, "GET", "/metrics", "", nil)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("metrics: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	for _, want := range []string{
		`stopbar_http_requests_total{route="/v1/evaluate",status="403"} 1`,
		`stopbar_http_requests_total{route="/v1/evaluate",status="400"} 1`,
		`stopbar_http_requests_total{route="other",status="404"} 2`, // unknown paths share one label
		`stopbar_gateway_rejections_total{code="MALFORMED_JSON"} 1`,
		`stopbar_decisions_total{outcome="deny"} 1`,
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("metrics missing %q:\n%s", want, b)
		}
	}
	if bytes.Contains(b, []byte("attacker-controlled")) {
		t.Error("request paths leaked into metric labels")
	}
}

// TestStatusAloneIsSafe: a client that checks only for 200 must never read
// a non-allow as an allow, and every outcome must have a status.
func TestStatusAloneIsSafe(t *testing.T) {
	for _, o := range []model.Outcome{model.Allow, model.Deny, model.Escalate} {
		s, ok := outcomeStatus[o]
		if !ok {
			t.Fatalf("no status for %s", o)
		}
		if (s == http.StatusOK) != (o == model.Allow) {
			t.Errorf("%s -> %d: 200 must mean allow and only allow", o, s)
		}
	}
}

func TestMaxSafeIntBoundary(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"a":9007199254740992}`: true, `{"a":-9007199254740992}`: true, `{"a":9007199254740993}`: false,
		`{"a":0.5}`: true, `{"a":1.5e300}`: false, `{"a":1e-300}`: true, `{"a":[1,2,{"b":99999999999999999}]}`: false,
	} {
		if err := checkIntegerPrecision([]byte(in)); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", in, err, ok)
		}
	}
}

// FuzzEvaluate: for any body, the gateway never panics, only answers with a
// known status, and returns 2xx only for a body that independently passes
// strict decoding and validation.
func FuzzEvaluate(f *testing.F) {
	for _, name := range []string{"action_request.evm_tx.json", "action_request.tool_call.json"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(`{"id":"a","id":"b"}`))
	f.Add([]byte(`{"ID":"x"}`))
	f.Add([]byte(`{"ttl_seconds":1e20}`))
	g := newGW(Config{Evaluator: decide(model.Allow), Nonces: alwaysFresh{}})
	f.Fuzz(func(t *testing.T, body []byte) {
		res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body)
		switch res.StatusCode {
		case 200:
			var r model.ActionRequest
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil || r.Validate() != nil {
				t.Fatalf("200 for a body that does not strictly validate: %q", body)
			}
		case 400, 413:
			errCode(t, b)
		default:
			t.Fatalf("unexpected status %d for %q", res.StatusCode, body)
		}
	})
}

// ---- CS-102: freshness and replay ----

// The window is two-sided: [issued_at - skew, issued_at + ttl + skew).
// The evm fixture has issued_at 10:00:00 and ttl 60s.
func TestFreshnessWindowEdges(t *testing.T) {
	base := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		now  time.Time
		want int
		code Code
	}{
		{"30s early is within skew", base.Add(-ClockSkew), 200, ""},
		{"30s+1ns early is in the future", base.Add(-ClockSkew - time.Nanosecond), 400, CodeIssuedInFuture},
		{"last instant before expiry", base.Add(60*time.Second + ClockSkew - time.Nanosecond), 200, ""},
		{"expired at ttl + skew", base.Add(60*time.Second + ClockSkew), 400, CodeExpired},
		{"long expired", base.Add(time.Hour), 400, CodeExpired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := tt.now
			g := newGW(Config{Evaluator: decide(model.Allow), Clock: func() time.Time { return now }})
			res, b := do(t, g, "POST", "/v1/evaluate", "application/json", fixture(t, "action_request.evm_tx.json"))
			if res.StatusCode != tt.want || (tt.code != "" && errCode(t, b) != tt.code) {
				t.Fatalf("got %d %s", res.StatusCode, b)
			}
		})
	}
}

// A nonce is spent before evaluation: replaying a denied request is
// rejected as a replay, not re-evaluated.
func TestNonceSpentEvenOnDeny(t *testing.T) {
	var evaluations atomic.Int64
	g := newGW(Config{Evaluator: evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		evaluations.Add(1)
		return decide(model.Deny)(ctx, r)
	})})
	body := fixture(t, "action_request.evm_tx.json")
	if res, _ := do(t, g, "POST", "/v1/evaluate", "application/json", body); res.StatusCode != 403 {
		t.Fatalf("first: %d", res.StatusCode)
	}
	res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body)
	if res.StatusCode != 400 || errCode(t, b) != CodeNonceReplayed || evaluations.Load() != 1 {
		t.Fatalf("replay: %d %s, evaluations=%d", res.StatusCode, b, evaluations.Load())
	}
	// Engine unavailable still spends the nonce.
	g = newGW(Config{})
	do(t, g, "POST", "/v1/evaluate", "application/json", body)
	if _, b := do(t, g, "POST", "/v1/evaluate", "application/json", body); errCode(t, b) != CodeNonceReplayed {
		t.Fatalf("nonce not spent when no engine: %s", b)
	}
}

func TestNonceScopedByTenantAndAgent(t *testing.T) {
	g := newGW(Config{Evaluator: decide(model.Allow)})
	post := func(tenant, agent string) int {
		res, _ := do(t, g, "POST", "/v1/evaluate", "application/json", mutate(t, func(m map[string]any) {
			m["tenant"] = tenant
			m["actor"].(map[string]any)["agent_id"] = agent
		}))
		return res.StatusCode
	}
	if post("acme", "a") != 200 || post("globex", "a") != 200 || post("acme", "b") != 200 {
		t.Fatal("the same nonce must be independent across tenants and agents")
	}
	if post("acme", "a") != 400 {
		t.Fatal("replay within (tenant, agent) accepted")
	}
}

// N concurrent identical requests: exactly one is evaluated.
func TestConcurrentReplayExactlyOneWins(t *testing.T) {
	const n = 200
	var evaluations atomic.Int64
	g := newGW(Config{Evaluator: evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		evaluations.Add(1)
		return decide(model.Allow)(ctx, r)
	})})
	body := fixture(t, "action_request.evm_tx.json")
	var ok, replayed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body)
			switch {
			case res.StatusCode == 200:
				ok.Add(1)
			case res.StatusCode == 400 && errCode(t, b) == CodeNonceReplayed:
				replayed.Add(1)
			default:
				t.Errorf("unexpected %d %s", res.StatusCode, b)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 || replayed.Load() != n-1 || evaluations.Load() != 1 {
		t.Fatalf("ok=%d replayed=%d evaluations=%d", ok.Load(), replayed.Load(), evaluations.Load())
	}
}

type brokenNonces struct{}

func (brokenNonces) Consume(string, time.Time) (bool, error) { return false, errors.New("disk full") }

func TestNonceStoreFailureFailsClosed(t *testing.T) {
	var evaluations atomic.Int64
	g := newGW(Config{Nonces: brokenNonces{}, Evaluator: evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		evaluations.Add(1)
		return decide(model.Allow)(ctx, r)
	})})
	res, b := do(t, g, "POST", "/v1/evaluate", "application/json", fixture(t, "action_request.evm_tx.json"))
	if res.StatusCode != 500 || errCode(t, b) != CodeInternal || evaluations.Load() != 0 {
		t.Fatalf("got %d %s, evaluations=%d", res.StatusCode, b, evaluations.Load())
	}
}
