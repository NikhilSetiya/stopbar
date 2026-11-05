package devstub

import (
	"context"
	"math/big"
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
	// Address poisoning lookalike.
	in.Destination = "0x1111000000000000000000000000000000001111"
	er = &model.EnrichedRequest{Request: model.ActionRequest{Action: evm("")}, Intent: in, Velocity: map[string]model.Velocity{}}
	if err := w.Enrich(context.Background(), er); err != nil || !er.Destination.SimilarToKnown || er.Destination.Known {
		t.Fatalf("lookalike: %+v %v", er.Destination, err)
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
}
