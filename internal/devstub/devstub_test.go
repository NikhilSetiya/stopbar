package devstub

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

var (
	_ engine.Decoder  = Decoder{}
	_ engine.Enricher = (*World)(nil)
	_ engine.AuditLog = (*Audit)(nil)
)

func evm(data string) model.Action {
	c, two := uint64(8453), 2
	return model.Action{Kind: model.KindEVMTx, ChainID: &c, From: "0x2222222222222222222222222222222222222222", To: "0x3333333333333333333333333333333333333333", ValueWei: "0", Data: data,
		TxType: &two, TxNonce: "0", GasLimit: "100000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"}
}

func TestExcessiveFeeFlag(t *testing.T) {
	for name, tt := range map[string]struct {
		gas, fee string
		flagged  bool
	}{
		"normal":                {"100000", "2000000000", false},
		"30M gas x 5000 gwei":   {"30000000", "5000000000000", true},
		"huge per-gas fee":      {"21000", "2000000000000", true},
		"huge gas limit":        {"20000000", "1", true},
		"0.05 ETH max fee edge": {"50000", "1000000000000", false},
	} {
		t.Run(name, func(t *testing.T) {
			a := evm("")
			a.GasLimit, a.MaxFeePerGas = tt.gas, tt.fee
			in, err := Decoder{}.Decode(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(in.Flags, "excessive_fee"); got != tt.flagged {
				t.Fatalf("flags %v", in.Flags)
			}
		})
	}
}

func TestDecoder(t *testing.T) {
	transfer := "0xa9059cbb0000000000000000000000009f30000000000000000000000000000000000c21000000000000000000000000000000000000000000027b46536c66c8e3000000"
	approveMax := "0x095ea7b3000000000000000000000000" + strings.Repeat("ab", 20) + strings.Repeat("f", 64)
	for name, tt := range map[string]struct {
		data, kind, dest string
		flags            []string
		err              bool
	}{
		"erc20 transfer":    {transfer, "transfer", "0x9f30000000000000000000000000000000000c21", nil, false},
		"native":            {"", "transfer", "0x3333333333333333333333333333333333333333", nil, false},
		"unlimited approve": {approveMax, "approve", "0x" + strings.Repeat("ab", 20), []string{"unlimited_approval"}, false},
		"unknown selector":  {"0xdeadbeef", "contract_call", "0x3333333333333333333333333333333333333333", []string{"unknown_call"}, false},
		"truncated":         {transfer[:70], "", "", nil, true},
		"dirty address":     {"0xa9059cbb" + strings.Repeat("1", 64) + strings.Repeat("0", 64), "", "", nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			in, err := Decoder{}.Decode(context.Background(), evm(tt.data))
			if (err != nil) != tt.err {
				t.Fatalf("err = %v", err)
			}
			if tt.err {
				return
			}
			if in.Kind != tt.kind || in.Destination != tt.dest || strings.Join(in.Flags, ",") != strings.Join(tt.flags, ",") {
				t.Fatalf("got %+v", in)
			}
		})
	}
}

func TestWorldEnrich(t *testing.T) {
	w := &World{
		KnownDestinations: []string{"0x1111111111111111111111111111111111111111"},
		Balances:          map[string]string{"DRB": "3000000"},
		PricesUSD:         map[string]string{"DRB": "0.058", "ETH": "3500"},
		Tokens:            map[string]Token{"0x3333333333333333333333333333333333333333": {Symbol: "DRB", Decimals: 18}},
	}
	in, err := Decoder{}.Decode(context.Background(), evm("0xa9059cbb0000000000000000000000009f30000000000000000000000000000000000c21000000000000000000000000000000000000000000027b46536c66c8e3000000"))
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

func TestAuditChains(t *testing.T) {
	var buf bytes.Buffer
	a := &Audit{W: &buf}
	for i := range 3 {
		if err := a.Append(context.Background(), model.AuditDecision, map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	prev := canon.GenesisHash
	for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var r model.AuditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		h, err := canon.RecordHash(r.Seq, r.TS, string(r.Type), r.Body, r.PrevHash)
		if err != nil || r.PrevHash != prev || r.Hash != h || r.Seq != uint64(i+1) {
			t.Fatalf("record %d breaks the chain: %+v", i, r)
		}
		prev = r.Hash
	}
}
