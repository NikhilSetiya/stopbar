package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestStoreTimeoutFailsClosed (CS-197, LLD §12): when the evaluation's state
// is not durable within the store timeout, the answer is a deny with
// FAIL_CLOSED_STORE: no token, no signed tx, never the withheld allow. It is
// counted on /metrics and logged at high severity. If the stalled write then
// fails (it was abandoned before committing), nothing lands and the nonce is
// reusable. If it lands anyway (it was already committing), Abandon is called
// to undo what it left.
func TestStoreTimeoutFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lands bool
	}{{"stalled before commit: nothing lands", false}, {"stalled while committing: lands late", true}} {
		t.Run(tc.name, func(t *testing.T) {
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
			release := make(chan struct{})
			var stalled atomic.Bool
			stalled.Store(true)
			eval := evalFunc(func(ctx context.Context, r model.ActionRequest) (model.Decision, error) {
				if !tc.lands { // stall inside the unit's writes, before the abandon check
					_ = db.Write(ctx, func(*bolt.Tx) error {
						if stalled.Load() {
							<-release
						}
						return nil
					}, nil)
				}
				d, err := decide(model.Allow)(ctx, r)
				d.Token, d.SignedTx, d.TxHash = "aGVhZA.cGF5bG9hZA.c2ln", "0x02f8", "0xabc"
				return d, err
			})
			if tc.lands { // stall after the writes, as a stuck fsync would
				var once sync.Once
				db.SetFaultForTest(func() error {
					once.Do(func() { <-release })
					return nil
				})
			}
			abandoned := make(chan string, 1)
			logs := &syncBuf{}
			g := newGW(Config{Nonces: ns, Evaluator: eval, State: db, StoreTimeout: 30 * time.Millisecond,
				Logger:  slog.New(slog.NewJSONHandler(logs, nil)),
				Abandon: func(_ context.Context, id string) { abandoned <- id }})
			body := fixture(t, "action_request.evm_tx.json")

			res, b := do(t, g, "POST", "/v1/evaluate", "application/json", body)
			var d model.Decision
			if err := json.Unmarshal(b, &d); err != nil {
				t.Fatalf("%d %s", res.StatusCode, b)
			}
			if res.StatusCode != 403 || d.Outcome != model.Deny || len(d.Reasons) != 1 || d.Reasons[0].Code != CodeStore {
				t.Fatalf("got %d %s, want 403 deny %s", res.StatusCode, b, CodeStore)
			}
			if d.Token != "" || d.SignedTx != "" || d.TxHash != "" || d.ReservationID != nil {
				t.Fatalf("FAIL_CLOSED_STORE answer leaks the withheld allow: %s", b)
			}
			if _, m := do(t, g, "GET", "/metrics", "", nil); !bytes.Contains(m, []byte("stopbar_store_timeouts_total 1")) {
				t.Fatalf("metric missing: %s", m)
			}
			if l := logs.String(); !bytes.Contains([]byte(l), []byte(`"severity":"high"`)) || !bytes.Contains([]byte(l), []byte(CodeStore)) {
				t.Fatalf("no high-severity log: %s", l)
			}

			stalled.Store(false)
			close(release)
			if tc.lands {
				select {
				case id := <-abandoned:
					if id != d.RequestID {
						t.Fatalf("abandoned %q, want %q", id, d.RequestID)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("a late-landing unit was not abandoned")
				}
				if recs, _ := audit.Records(db, 0, 0); len(recs) == 0 {
					t.Fatal("the late unit did not land")
				}
				return
			}
			// Until the abandoned unit settles its nonce is pending (a replay);
			// once it has failed, the nonce is free again.
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if res, _ = do(t, g, "POST", "/v1/evaluate", "application/json", body); res.StatusCode != 400 {
					break
				}
			}
			if res.StatusCode != 200 {
				t.Fatalf("retry after an abandoned unit: %d, want 200 (nothing was recorded)", res.StatusCode)
			}
			select {
			case id := <-abandoned:
				t.Fatalf("Abandon(%s) called for a unit that never landed", id)
			default:
			}
		})
	}
}
