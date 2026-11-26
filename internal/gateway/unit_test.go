package gateway

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// TestEvaluationIsOneUnit (CS-197): with a state file, the nonce, its request
// record and the evaluator's writes are one transaction, and the decision is
// answered only once it is durable. If the transaction fails, the caller gets
// a 500 (never the decision), nothing of the evaluation is on disk, and the
// nonce is not spent: the same request can be sent again.
func TestEvaluationIsOneUnit(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := nonce.Open(db, "nonces_v1", lg, func() time.Time { return fixtureTime })
	if err != nil {
		t.Fatal(err)
	}
	failWrite := true
	var txIDs []int
	eval := evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
		if err := lg.Append(ctx, model.AuditDecision, map[string]any{"request_id": r.ID}); err != nil {
			return model.Decision{}, err
		}
		_ = db.Write(ctx, func(tx *bolt.Tx) error {
			txIDs = append(txIDs, tx.ID())
			if failWrite {
				return errors.New("disk full")
			}
			return nil
		}, nil)
		return decide(model.Allow)(ctx, r)
	})
	g := newGW(Config{Nonces: ns, Evaluator: eval, State: db})
	body := fixture(t, "action_request.evm_tx.json")

	res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body)
	if res.StatusCode != 500 || errCode(t, b) != CodeInternal {
		t.Fatalf("failed unit: got %d %s, want 500", res.StatusCode, b)
	}
	if recs, _ := audit.Records(db, 0, 0); len(recs) != 0 {
		t.Fatalf("%d audit records after a failed unit", len(recs))
	}
	if _, b := do(t, g, "GET", "/metrics", "", nil); !bytes.Contains(b, []byte("stopbar_state_write_failures_total 1")) {
		t.Fatalf("metric missing: %s", b)
	}

	failWrite = false
	res, b = do(t, g, "POST", "/v1/evaluate", "application/json", body)
	if res.StatusCode != 200 {
		t.Fatalf("retry after a failed unit: got %d %s, want 200 (the nonce was never spent)", res.StatusCode, b)
	}
	recs, _ := audit.Records(db, 0, 0)
	if len(recs) != 2 || recs[0].Type != model.AuditRequest || recs[1].Type != model.AuditDecision {
		t.Fatalf("records %+v, want request then decision", recs)
	}
	if res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body); res.StatusCode != 400 || errCode(t, b) != CodeNonceReplayed {
		t.Fatalf("replay after commit: got %d %s, want NONCE_REPLAYED", res.StatusCode, b)
	}
	if len(txIDs) != 2 {
		t.Fatalf("evaluator write ran %d times", len(txIDs))
	}
}
