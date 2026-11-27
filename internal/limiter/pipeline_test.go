package limiter_test

// Pipeline tests: the real engine, EVM decoder, starter policy bundle, decision
// signer, audit log and limiter (on bbolt), with the devstub world from the
// corpus. They pin the caps end to end, not just inside the limiter.

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/policy"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// testApprovers configures three Ed25519 approver keys for tenant "test"
// (CS-151), each with its own distinct owner, shared by the pipeline tests
// below: alice/bob for the breaker's 2-of-N reset, approver for the
// single-signer escalation-approval flow.
func testApprovers(t *testing.T) (*approval.KeySet, map[string]ed25519.PrivateKey) {
	t.Helper()
	privs := map[string]ed25519.PrivateKey{}
	var keys []approval.Key
	for _, id := range []string{"alice", "bob", "approver"} {
		pub, priv, err := approval.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		privs[id] = priv
		keys = append(keys, approval.Key{ID: id, Tenant: "test", Owner: approval.Owner{KeyID: "ak_" + id}, Public: pub})
	}
	ks, err := approval.NewKeySet(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ks, privs
}

// signApprove builds a signed escalation-approval envelope for id/payloadHash
// under the policy bundle bundleHash.
func signApprove(t *testing.T, priv ed25519.PrivateKey, id, payloadHash, bundleHash string) approval.SignedEscalation {
	t.Helper()
	s, err := approval.SignEscalation(priv, approval.EscalationObject{
		EscalationID: id, PayloadHash: payloadHash, PolicyBundleHash: bundleHash, Decision: approval.Approve, Expiry: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signReset builds a signed breaker-reset envelope for tenant/tripID.
func signReset(t *testing.T, priv ed25519.PrivateKey, tenant, tripID string) approval.SignedBreakerReset {
	t.Helper()
	s, err := approval.SignBreakerReset(priv, approval.BreakerResetObject{
		Tenant: tenant, TripRequestID: tripID, Decision: approval.ResetDecision, Expiry: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var bg = context.Background()

type memPending struct {
	mu  sync.Mutex
	m   map[string]engine.PendingEscalation
	log *audit.Log // Put appends its audit record here
}

func (p *memPending) Put(ctx context.Context, e engine.PendingEscalation, rec *model.AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rec != nil {
		if err := p.log.Append(ctx, rec.Type, rec.Body); err != nil {
			return err
		}
	}
	p.m[e.Request.ID] = e
	return nil
}

func (p *memPending) Get(_ context.Context, id string) (engine.PendingEscalation, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[id]
	return e, ok, nil
}

type pipeline struct {
	eng    *engine.Engine
	lim    *limiter.Limiter
	db     *store.DB
	log    *audit.Log
	keys   map[string]ed25519.PublicKey
	approv map[string]ed25519.PrivateKey // approver keys (CS-151): alice, bob, approver
}

// openClawWorld is corpus CS-2026-0002's setup: 52,430,000 LOBSTAR at $0.00477.
func openClawWorld(limits ...limiter.Rule) *devstub.World {
	return &devstub.World{
		KnownDestinations: []string{"0x4444444444444444444444444444444444444444"},
		Balances:          map[string]string{"LOBSTAR": "52430000"},
		PricesUSD:         map[string]string{"ETH": "3500", "LOBSTAR": "0.00477"},
		Tokens:            map[string]devstub.Token{"0x6666666666666666666666666666666666666666": {Symbol: "LOBSTAR", Decimals: 18}},
		Limits:            limits,
	}
}

func newPipeline(t *testing.T, w *devstub.World, cfg limiter.Config) *pipeline {
	t.Helper()
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, dk, _ := ed25519.GenerateKey(nil)
	ring := decision.NewKeyRing(dk)
	lg, err := audit.New(audit.Config{DB: db, Signer: ring})
	if err != nil {
		t.Fatal(err)
	}
	st, err := limiter.NewBoltStore(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	approvers, approvPrivs := testApprovers(t)
	cfg.Rules, cfg.Store, cfg.Approvers = w.Limits, st, approvers
	lim, err := limiter.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Load("../../examples/policies")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		Decoders: []engine.Decoder{evm.Decoder{}}, Enrichers: []engine.Enricher{w, lim},
		Policy: b, Limiter: lim, Audit: lg,
		Signer:         &decision.Signer{Keys: ring, Iss: "stopbar:test", Aud: "signer:test"},
		Pending:        &memPending{m: map[string]engine.PendingEscalation{}, log: lg},
		Approvers:      approvers,
		ApprovalQuorum: 1, // single-signer flow for these tests; the breaker's own quorum is set via cfg.BreakerQuorum
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pipeline{eng: eng, lim: lim, db: db, log: lg, keys: ring.PublicKeys(), approv: approvPrivs}
}

// transfer builds a LOBSTAR transfer to the known destination. tokens is the
// calldata's 32-byte amount word (hex, no 0x).
func transfer(id, tenant, amountWord string) model.ActionRequest {
	chain, two := uint64(8453), 2
	return model.ActionRequest{
		ID: id, Tenant: tenant, Nonce: "bm9uY2Utbm9uY2Utbm9uY2U", IssuedAt: time.Now(), TTLSeconds: 60,
		Actor: model.Actor{AgentID: "defi-agent"},
		Action: model.Action{Kind: model.KindEVMTx, ChainID: &chain,
			From: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", To: "0x6666666666666666666666666666666666666666", ValueWei: "0",
			Data:   "0xa9059cbb0000000000000000000000004444444444444444444444444444444444444444" + amountWord,
			TxType: &two, TxNonce: "0", GasLimit: "100000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"},
		Provenance: model.Provenance{Labels: []string{"trusted_user"}},
	}
}

const (
	fullBalance = "0000000000000000000000000000000000000000002b5e7bfec382a0a4c00000" // 52,430,000e18: 100%, ~$250,091
	tenthOfBal  = "00000000000000000000000000000000000000000004563f9979f37676e00000" // 5,243,000e18: 10%, ~$25,009
	tinyAmount  = "0000000000000000000000000000000000000000000000056bc75e2d63100000" // 100e18: ~$0.48
)

func reasonIDs(d model.Decision) (ids, codes []string) {
	for _, r := range d.Reasons {
		if r.PolicyID != "" {
			ids = append(ids, r.PolicyID)
		}
		codes = append(codes, r.Code)
	}
	return ids, codes
}

// CS-124 acceptance through the whole pipeline: an outflow breach trips the
// tenant breaker; from then on every request for the tenant (a tiny transfer,
// one that would only escalate, an approval) is denied CIRCUIT_OPEN, the trip
// metric is up, one approver cannot reset it, and two can. The audit chain
// (trip, vote, reset in the same transactions) verifies.
func TestCircuitBreakerThroughEngine(t *testing.T) {
	w := openClawWorld(
		limiter.Rule{Scope: limiter.ScopeTenant, Window: "1h", MaxUSD: "30000", CircuitBreaker: true},
		limiter.Rule{Scope: limiter.ScopeWallet, Window: "1h", MaxUSD: "1000000"},
	)
	p := newPipeline(t, w, limiter.Config{BreakerQuorum: 2})
	code := func(d model.Decision) string { _, c := reasonIDs(d); return c[len(c)-1] }

	d, _ := p.eng.Evaluate(bg, transfer("req_0", "test", tenthOfBal))
	if d.Outcome != model.Allow {
		t.Fatalf("first transfer: %s %v", d.Outcome, d.Reasons)
	}
	if err := p.eng.Commit(bg, "req_0", "0xabc"); err != nil {
		t.Fatal(err)
	}
	// An escalation recorded before the trip, to approve after it.
	escD, _ := p.eng.Evaluate(bg, transfer("req_esc", "test", fullBalance))
	if escD.Outcome != model.Escalate {
		t.Fatalf("pre-trip escalation: %s %v", escD.Outcome, escD.Reasons)
	}
	d, _ = p.eng.Evaluate(bg, transfer("req_1", "test", tenthOfBal)) // $50k > $30k: trips
	if d.Outcome != model.Deny || code(d) != engine.CodeCircuitOpen {
		t.Fatalf("breach: %s %v, want deny CIRCUIT_OPEN", d.Outcome, d.Reasons)
	}
	for _, id := range []string{"req_2", "req_3"} {
		amt := map[string]string{"req_2": tinyAmount, "req_3": fullBalance}[id]
		if d, _ := p.eng.Evaluate(bg, transfer(id, "test", amt)); d.Outcome != model.Deny || code(d) != engine.CodeCircuitOpen {
			t.Fatalf("%s after trip: %s %v, want deny CIRCUIT_OPEN", id, d.Outcome, d.Reasons)
		}
	}
	if d, _ := p.eng.Approve(bg, "req_esc", signApprove(t, p.approv["alice"], "req_esc", escD.PayloadHash, p.eng.PolicyBundleHash())); d.Outcome != model.Deny || code(d) != engine.CodeCircuitOpen {
		t.Fatalf("approval after trip: %s %v, want deny CIRCUIT_OPEN", d.Outcome, d.Reasons)
	}
	if d, _ := p.eng.Evaluate(bg, transfer("req_other", "other-tenant", tinyAmount)); d.Outcome != model.Allow {
		t.Fatalf("another tenant was halted: %s %v", d.Outcome, d.Reasons)
	}
	if got := p.lim.Counters()["stopbar_circuit_breaker_trips_total"]; got != 1 {
		t.Fatalf("trip metric %d, want 1", got)
	}

	if st, err := p.lim.ResetBreaker(bg, "test", signReset(t, p.approv["alice"], "test", "req_1")); err != nil || !st.Open {
		t.Fatalf("one vote: %+v %v", st, err)
	}
	if d, _ := p.eng.Evaluate(bg, transfer("req_4", "test", tinyAmount)); code(d) != engine.CodeCircuitOpen {
		t.Fatalf("after one of two votes: %s %v", d.Outcome, d.Reasons)
	}
	if st, err := p.lim.ResetBreaker(bg, "test", signReset(t, p.approv["bob"], "test", "req_1")); err != nil || st.Open {
		t.Fatalf("quorum: %+v %v", st, err)
	}
	if d, _ := p.eng.Evaluate(bg, transfer("req_5", "test", tinyAmount)); d.Outcome != model.Allow {
		t.Fatalf("after reset: %s %v", d.Outcome, d.Reasons)
	}

	if err := p.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Verify(p.db, p.keys, 1, 0)
	if err != nil || rep.Uncovered != 0 {
		t.Fatalf("audit verify: %+v %v", rep, err)
	}
}

// CS-123 acceptance: the OpenClaw fixture (CS-2026-0002, agent sends its whole
// balance) escalates for the balance-share policy, and the hard per-tx caps in
// the limiter config still hold when a human approves it: approval waives the
// escalation, never a cap.
func TestOpenClawEscalatesAndPerTxCapsSurviveApproval(t *testing.T) {
	for _, c := range []struct {
		name  string
		rules []limiter.Rule
		want  string // outcome after approval
	}{
		{"absolute per-tx cap", []limiter.Rule{{Scope: limiter.ScopeWallet, Window: limiter.WindowTx, MaxUSD: "10000"}}, engine.CodeCapExceeded},
		{"pct-of-balance per-tx cap", []limiter.Rule{{Scope: limiter.ScopeWallet, Window: limiter.WindowTx, MaxPctOfBalance: "0.5"}}, engine.CodeCapExceeded},
		{"caps that fit", []limiter.Rule{{Scope: limiter.ScopeWallet, Window: limiter.WindowTx, MaxUSD: "300000", MaxPctOfBalance: "1"}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPipeline(t, openClawWorld(c.rules...), limiter.Config{})
			d, _ := p.eng.Evaluate(bg, transfer("req_openclaw", "test", fullBalance))
			ids, _ := reasonIDs(d)
			if d.Outcome != model.Escalate || len(ids) != 1 || ids[0] != "large-share-of-balance" {
				t.Fatalf("OpenClaw: %s %v, want escalate [large-share-of-balance]", d.Outcome, d.Reasons)
			}
			d, err := p.eng.Approve(bg, "req_openclaw", signApprove(t, p.approv["approver"], "req_openclaw", d.PayloadHash, p.eng.PolicyBundleHash()))
			if err != nil {
				t.Fatal(err)
			}
			_, codes := reasonIDs(d)
			switch {
			case c.want == "" && d.Outcome != model.Allow:
				t.Fatalf("approved under fitting caps: %s %v, want allow", d.Outcome, d.Reasons)
			case c.want != "" && (d.Outcome != model.Deny || len(codes) != 1 || codes[0] != c.want):
				t.Fatalf("approved over a hard cap: %s %v, want deny %s", d.Outcome, d.Reasons, c.want)
			}
		})
	}
}
