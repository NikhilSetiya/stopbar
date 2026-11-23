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

var bg = context.Background()

type memPending struct {
	mu sync.Mutex
	m  map[string]engine.PendingEscalation
}

func (p *memPending) Put(_ context.Context, e engine.PendingEscalation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[e.Request.ID] = e
	return nil
}

func (p *memPending) Get(_ context.Context, id string) (engine.PendingEscalation, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[id]
	return e, ok, nil
}

func (p *memPending) Delete(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, id)
	return nil
}

type pipeline struct {
	eng *engine.Engine
	lim *limiter.Limiter
	db  *store.DB
	log *audit.Log
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
	cfg.Rules, cfg.Store = w.Limits, st
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
		Signer:  &decision.Signer{Keys: ring, Iss: "stopbar:test", Aud: "signer:test"},
		Pending: &memPending{m: map[string]engine.PendingEscalation{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pipeline{eng: eng, lim: lim, db: db, log: lg}
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
			d, _, err := p.eng.Approve(bg, "req_openclaw", "ak_approver")
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
