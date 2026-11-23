package devstub

import (
	"context"
	"math/big"
	"slices"
	"testing"

	evmdec "github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

var (
	_ engine.Enricher = (*World)(nil)
)

func evm(data string) model.Action {
	c, two := uint64(8453), 2
	return model.Action{Kind: model.KindEVMTx, ChainID: &c, From: "0x2222222222222222222222222222222222222222", To: "0x3333333333333333333333333333333333333333", ValueWei: "0", Data: data,
		TxType: &two, TxNonce: "0", GasLimit: "100000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"}
}

func TestWorldEnrich(t *testing.T) {
	w := &World{
		KnownDestinations: []string{"0x1111111111111111111111111111111111111111"},
		Balances:          map[string]string{"DRB": "3000000"},
		PricesUSD:         map[string]string{"DRB": "0.058", "ETH": "3500"},
		Tokens:            map[string]Token{"0x3333333333333333333333333333333333333333": {Symbol: "DRB", Decimals: 18}},
	}
	in, err := evmdec.Decoder{}.Decode(context.Background(), evm("0xa9059cbb0000000000000000000000009f30000000000000000000000000000000000c21000000000000000000000000000000000000000000027b46536c66c8e3000000"))
	if err != nil {
		t.Fatal(err)
	}
	er := &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Intent: in, Velocity: map[string]model.Velocity{}}
	if err := w.Enrich(context.Background(), er); err != nil {
		t.Fatal(err)
	}
	if er.MaxFeeUSD == nil || *er.MaxFeeUSD != "0.7" { // 100,000 gas x 2 gwei = 0.0002 ETH x $3,500
		t.Fatalf("max fee usd %v", er.MaxFeeUSD)
	}
	if *er.AmountUSD != "174000" || *er.PctOfBalance != "1" || er.PriceStale || er.Destination.Known {
		t.Fatalf("got amount=%v pct=%v %+v", *er.AmountUSD, *er.PctOfBalance, er)
	}

	// Missing price: stale and no amount, so policy fails closed.
	w.PricesUSD = nil
	er = &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Intent: in, Velocity: map[string]model.Velocity{}}
	if err := w.Enrich(context.Background(), er); err != nil || er.AmountUSD != nil || !er.PriceStale {
		t.Fatalf("missing price: %+v %v", er, err)
	}
	// Destination facts come from the registry (enrich.Registry), not the stub.
	if er.Destination.Known || er.Destination.SimilarToKnown {
		t.Fatalf("stub set destination facts: %+v", er.Destination)
	}
}

// excessive_slippage from the static prices (CS-145): 5,000 USDC for WETH at
// $3,500 should yield ~1.4286 WETH; with the default 3% a minimum below
// ~1.3857 is flagged. WETH is priced as ETH; an unknown token can't be
// priced, so the swap marks the price stale.
func TestWorldSlippage(t *testing.T) {
	const usdc, weth, other = "0x3333333333333333333333333333333333333333", "0x4200000000000000000000000000000000000006", "0x5555555555555555555555555555555555555555"
	w := &World{PricesUSD: map[string]string{"ETH": "3500", "USDC": "1"},
		Tokens: map[string]Token{usdc: {Symbol: "USDC", Decimals: 6}}}
	for _, tt := range []struct {
		name     string
		out      string // token out
		minOut   string
		flagged  bool
		stale    bool
		maxSlipp string
	}{
		{"within 3%", weth, "1400000000000000000", false, false, ""},
		{"just inside the 3% bound", weth, "1385714285714285715", false, false, ""},
		{"5% short", weth, "1357142857142857142", true, false, ""},
		{"zero min out", weth, "0", true, false, ""},
		{"5% short but the tenant allows 10%", weth, "1357142857142857142", false, false, "0.10"},
		{"unpriced output token", other, "1", false, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w.MaxSlippage = tt.maxSlipp
			in := model.IntentSummary{Kind: "transfer", Op: "swap_exact_in", Asset: &model.Asset{ChainID: 8453, Address: usdc}, Amount: "5000000000",
				Destination: "0x2222222222222222222222222222222222222222", Flags: []string{},
				Swap: &model.Swap{ExactIn: true, TokenIn: usdc, AmountIn: "5000000000", TokenOut: tt.out, AmountOut: tt.minOut}}
			er := &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Intent: in, Velocity: map[string]model.Velocity{}}
			if err := w.Enrich(context.Background(), er); err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(er.Intent.Flags, "excessive_slippage"); got != tt.flagged || er.PriceStale != tt.stale {
				t.Fatalf("flagged=%v stale=%v, want %v %v (flags %v)", got, er.PriceStale, tt.flagged, tt.stale, er.Intent.Flags)
			}
		})
	}
}

func TestDecimalStringRoundsUp(t *testing.T) {
	r, _ := new(big.Rat).SetString("1/3")
	if got := *decimalString(r); got != "0.333333333333333334" {
		t.Fatalf("1/3 -> %s", got)
	}
}

// A batch with several outflows has no single amount. Reading that as $0
// would slip it under every cap, so it fails closed until CS-131 prices
// outflows; an approval moves no funds when made, so it is $0 of spend.
func TestBatchesAndApprovalsArePricedSafely(t *testing.T) {
	w := &World{PricesUSD: map[string]string{"ETH": "3500", "DRB": "1"},
		Tokens: map[string]Token{"0x3333333333333333333333333333333333333333": {Symbol: "DRB", Decimals: 18}}}
	er := &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Velocity: map[string]model.Velocity{},
		Intent: model.IntentSummary{Kind: "contract_call", Flags: []string{"multi_transfer"}}}
	if err := w.Enrich(context.Background(), er); err == nil {
		t.Fatal("multi_transfer batch was priced; must fail closed")
	}
	max := "115792089237316195423570985008687907853269984665640564039457584007913129639935"
	er = &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Velocity: map[string]model.Velocity{},
		Intent: model.IntentSummary{Kind: "approve", Asset: &model.Asset{ChainID: 8453, Address: "0x3333333333333333333333333333333333333333"}, Amount: max, Flags: []string{"unlimited_approval"}}}
	if err := w.Enrich(context.Background(), er); err != nil || er.AmountUSD == nil || *er.AmountUSD != "0" {
		t.Fatalf("approval priced as spend: %v %v", er.AmountUSD, err)
	}
	if er.ApprovalUSD != nil {
		t.Fatalf("unlimited approval got a value %s; it must have none", *er.ApprovalUSD)
	}
	// A bounded approval carries its value (250 DRB at $1), so policy can cap it.
	er = &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Velocity: map[string]model.Velocity{},
		Intent: model.IntentSummary{Kind: "approve", Asset: &model.Asset{ChainID: 8453, Address: "0x3333333333333333333333333333333333333333"}, Amount: "250000000000000000000", Flags: []string{}}}
	if err := w.Enrich(context.Background(), er); err != nil || er.ApprovalUSD == nil || *er.ApprovalUSD != "250" || *er.AmountUSD != "0" {
		t.Fatalf("bounded approval: approval_usd %v amount_usd %v %v", er.ApprovalUSD, er.AmountUSD, err)
	}
}
