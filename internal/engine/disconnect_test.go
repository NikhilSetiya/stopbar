package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// slowAudit is the real audit log with a few milliseconds of latency, so a
// cancelled request context reliably wins any race against the write.
type slowAudit struct{ log *audit.Log }

func (s slowAudit) Append(ctx context.Context, typ model.AuditRecordType, body any) error {
	time.Sleep(5 * time.Millisecond)
	return s.log.Append(ctx, typ, body)
}

type slowLimiter struct{ *fakeLimiter }

func (s slowLimiter) Commit(ctx context.Context, id, txRef string, rec *model.AuditEntry) error {
	time.Sleep(5 * time.Millisecond)
	return s.fakeLimiter.Commit(ctx, id, txRef, rec)
}

func (s slowLimiter) Release(ctx context.Context, id string, rec *model.AuditEntry) error {
	time.Sleep(5 * time.Millisecond)
	return s.fakeLimiter.Release(ctx, id, rec)
}

// doneEvaluator signals when the engine has finished a request, whether or
// not anyone is still listening for the answer.
type doneEvaluator struct {
	e    *Engine
	done chan model.Decision
}

func (d doneEvaluator) Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error) {
	out, err := d.e.Evaluate(ctx, req)
	d.done <- out
	return out, err
}

// A client that hangs up mid-request must not be able to make a decision go
// unaudited: the decision is recorded, it is not counted as an unaudited
// denial, and the log verifies offline. (The request context is cancelled
// on disconnect; the audit write must not inherit that cancellation.)
func TestClientDisconnectMidRequestIsAudited(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, k, _ := ed25519.GenerateKey(nil)
	ring := decision.NewKeyRing(k)
	log, err := audit.New(audit.Config{DB: db, Signer: ring})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(fixtureRequest(t, "action_request.evm_tx.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixtureNow := func() time.Time { return time.Date(2026, 11, 2, 10, 0, 10, 0, time.UTC) }

	const n = 10
	for i := range n {
		entered := make(chan struct{})
		r := newRig()
		r.cfg.Audit = slowAudit{log}
		r.cfg.StageTimeout = 2 * time.Second
		r.cfg.Enrichers = []Enricher{enrichFunc(func(ctx context.Context, _ *model.EnrichedRequest) error {
			close(entered) // the request is mid-pipeline; now the client hangs up
			<-ctx.Done()
			return ctx.Err()
		})}
		ev := doneEvaluator{r.engine(t), make(chan model.Decision, 1)}
		srv := httptest.NewServer(gateway.New(gateway.Config{Evaluator: ev, Clock: fixtureNow}))

		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/evaluate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		go func() {
			if res, err := http.DefaultClient.Do(req); err == nil {
				_ = res.Body.Close()
			}
		}()
		<-entered
		cancel()

		var d model.Decision
		select {
		case d = <-ev.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d: engine never finished after the disconnect", i)
		}
		srv.Close()
		if d.Outcome != model.Deny || d.Reasons[len(d.Reasons)-1].Code != CodeEnrich {
			t.Fatalf("request %d: want a FAIL_CLOSED_ENRICH deny, got %s %+v", i, d.Outcome, d.Reasons)
		}
		if got := ev.e.Counters()["stopbar_audit_unavailable_denials_total"]; got != 0 {
			t.Fatalf("request %d: disconnect counted %d unaudited denial(s); the decision must be audited", i, got)
		}
	}

	if err := log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Verify(db, ring.PublicKeys(), 0, 0)
	if err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	if rep.Records != n || rep.Uncovered != 0 {
		t.Fatalf("want %d audited decisions, all covered by a checkpoint; got %+v", n, rep)
	}
}

// Commit and Release record a state change that has already happened (a
// signed transaction, an abandoned allow). A caller that goes away must not
// stop them being written.
func TestCommitAndReleaseSurviveCallerCancellation(t *testing.T) {
	r := newRig()
	r.cfg.Limiter = slowLimiter{r.limiter}
	e := r.engine(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()

	for i, op := range []string{"commit", "release"} {
		req := fixtureRequest(t, "action_request.evm_tx.json")
		req.ID = req.ID + "-" + op
		if d := evaluate(t, e, req); d.Outcome != model.Allow {
			t.Fatalf("%s: setup allow failed: %+v", op, d.Reasons)
		}
		var err error
		if op == "commit" {
			err = e.Commit(gone, req.ID, "0xabc")
		} else {
			err = e.Release(gone, req.ID, "client")
		}
		if err != nil {
			t.Fatalf("%s after the caller went away: %v", op, err)
		}
		if got := len(r.audit.records); got != 2*(i+1) {
			t.Fatalf("%s: %d audit records, want %d (allow + %s)", op, got, 2*(i+1), op)
		}
	}
}
