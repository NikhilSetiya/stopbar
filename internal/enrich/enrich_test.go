package enrich

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// ---- a mock JSON-RPC node ----

const (
	wallet   = "0x1111111111111111111111111111111111111111"
	usdc     = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
	ethFeed  = "0x71041dddad3595f9ced3dccfbe3d1f4b0a16bb70" // Base ETH/USD
	usdcFeed = "0x7e860098f58bbfc8648a4311b374b1d669a2bc6b" // Base USDC/USD
)

// word left-pads a big.Int to a 32-byte ABI word (hex, no 0x).
func word32(n *big.Int) string {
	b := n.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return hex.EncodeToString(out)
}

// roundData encodes latestRoundData() with the given answer and updatedAt.
func roundData(answer int64, updatedAt time.Time) string {
	return "0x" + word32(big.NewInt(1)) + word32(big.NewInt(answer)) + word32(big.NewInt(0)) +
		word32(big.NewInt(updatedAt.Unix())) + word32(big.NewInt(1))
}

// mockNode answers eth_getBalance and eth_call for a fixed world. It counts
// calls so tests can assert caching.
type mockNode struct {
	now       time.Time
	ethWei    *big.Int
	usdcUnits *big.Int
	calls     map[string]int
	srv       *httptest.Server
}

func newMockNode(now time.Time) *mockNode {
	m := &mockNode{now: now, ethWei: new(big.Int), usdcUnits: new(big.Int), calls: map[string]int{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

func (m *mockNode) handle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
		ID     uint64 `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m.calls[req.Method]++
	reply := func(result string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	switch req.Method {
	case "eth_getBalance":
		reply("0x" + m.ethWei.Text(16))
	case "eth_call":
		p := req.Params[0].(map[string]any)
		to, data := strings.ToLower(p["to"].(string)), p["data"].(string)
		sel := strings.TrimPrefix(data, "0x")[:8]
		m.calls["eth_call:"+to+":"+sel]++
		switch {
		case sel == selDecimals && to == usdc:
			reply("0x" + word32(big.NewInt(6)))
		case sel == selDecimals: // feed decimals (Chainlink USD feeds are 8)
			reply("0x" + word32(big.NewInt(8)))
		case sel == selBalanceOf && to == usdc:
			reply("0x" + word32(m.usdcUnits))
		case sel == selLatestRoundData && to == ethFeed:
			reply(roundData(3500e8, m.now))
		case sel == selLatestRoundData && to == usdcFeed:
			reply(roundData(1e8, m.now))
		default:
			reply("0x" + word32(big.NewInt(0)))
		}
	default:
		http.Error(w, "unexpected method "+req.Method, 400)
	}
}

func (m *mockNode) enricher(t *testing.T) *ChainEnricher {
	t.Helper()
	e, err := New(Config{
		RPCURL: m.srv.URL,
		Feeds:  map[string]string{NativeKey: ethFeed, usdc: usdcFeed},
		Clock:  func() time.Time { return m.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ethTx(from, to, valueWei string) model.EnrichedRequest {
	return model.EnrichedRequest{
		Request: model.ActionRequest{Action: model.Action{
			Kind: model.KindEVMTx, From: from, To: to, ValueWei: valueWei,
			GasLimit: "21000", MaxFeePerGas: "200000000",
		}},
		Intent: model.IntentSummary{Kind: "transfer", Amount: valueWei, Destination: to},
	}
}

// ---- tests ----

func TestBalanceProviderNativeAndERC20(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei, _ = new(big.Int).SetString("5000000000000000000", 10) // 5 ETH
	m.usdcUnits = big.NewInt(1234_000000)                           // 1234 USDC (6 dp)
	b := NewBalanceProvider(NewRPC(m.srv.URL, 0), 0)

	got, err := b.Balance(context.Background(), wallet, "")
	if err != nil || got.String() != "5000000000000000000" {
		t.Fatalf("native balance = %v, %v", got, err)
	}
	got, err = b.Balance(context.Background(), wallet, usdc)
	if err != nil || got.String() != "1234000000" {
		t.Fatalf("usdc balance = %v, %v", got, err)
	}
	d, err := b.Decimals(context.Background(), usdc)
	if err != nil || d != 6 {
		t.Fatalf("usdc decimals = %v, %v", d, err)
	}
}

func TestBalanceCacheHitsRPCOnce(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei = big.NewInt(42)
	b := NewBalanceProvider(NewRPC(m.srv.URL, 0), time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := b.Balance(context.Background(), wallet, ""); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls["eth_getBalance"] != 1 {
		t.Fatalf("eth_getBalance called %d times, want 1 (cached)", m.calls["eth_getBalance"])
	}
}

func TestPriceOracleFreshAndStale(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newMockNode(now)
	o := NewPriceOracle(NewRPC(m.srv.URL, 0), map[string]string{NativeKey: ethFeed, usdc: usdcFeed}, time.Hour, 0)
	o.clock = func() time.Time { return now }

	p, stale := o.Price(context.Background(), NativeKey)
	if stale || p.FloatString(2) != "3500.00" {
		t.Fatalf("ETH price = %v stale=%v, want 3500", p, stale)
	}

	// A feed that last updated two hours ago is stale (maxAge 1h).
	m.now = now.Add(-2 * time.Hour)
	o2 := NewPriceOracle(NewRPC(m.srv.URL, 0), map[string]string{NativeKey: ethFeed}, time.Hour, 0)
	o2.clock = func() time.Time { return now }
	if _, stale := o2.Price(context.Background(), NativeKey); !stale {
		t.Fatal("a two-hour-old feed should be stale")
	}

	// An asset with no configured feed is stale, not an error.
	if _, stale := o.Price(context.Background(), "0xdeadbeef"); !stale {
		t.Fatal("an asset with no feed should be stale")
	}
}

func TestEnrichNativeTransfer(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei, _ = new(big.Int).SetString("10000000000000000000", 10) // 10 ETH balance
	er := ethTx(wallet, "0x2222222222222222222222222222222222222222", "5000000000000000000")
	if err := m.enricher(t).Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	if er.PriceStale {
		t.Fatal("price should not be stale")
	}
	if er.AmountUSD == nil || *er.AmountUSD != "17500" { // 5 ETH * $3500
		t.Fatalf("AmountUSD = %v, want 17500", str(er.AmountUSD))
	}
	if er.PctOfBalance == nil || *er.PctOfBalance != "0.5" { // 5 of 10 ETH
		t.Fatalf("PctOfBalance = %v, want 0.5", str(er.PctOfBalance))
	}
	if er.MaxFeeUSD == nil { // 21000 * 0.2 gwei * $3500 > 0
		t.Fatal("MaxFeeUSD should be set")
	}
}

func TestEnrichERC20Transfer(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei = big.NewInt(1e18)           // for the fee
	m.usdcUnits = big.NewInt(2000_000000) // 2000 USDC balance
	er := model.EnrichedRequest{
		Request: model.ActionRequest{Action: model.Action{
			Kind: model.KindEVMTx, From: wallet, To: usdc, ValueWei: "0",
			GasLimit: "60000", MaxFeePerGas: "200000000",
		}},
		Intent: model.IntentSummary{
			Kind: "transfer", Amount: "500000000", Destination: "0x3333333333333333333333333333333333333333",
			Asset: &model.Asset{Address: usdc},
		},
	}
	if err := m.enricher(t).Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	if er.AmountUSD == nil || *er.AmountUSD != "500" { // 500 USDC * $1
		t.Fatalf("AmountUSD = %v, want 500", str(er.AmountUSD))
	}
	if er.PctOfBalance == nil || *er.PctOfBalance != "0.25" { // 500 of 2000
		t.Fatalf("PctOfBalance = %v, want 0.25", str(er.PctOfBalance))
	}
}

func TestEnrichStalePriceLeavesNoAmount(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei = big.NewInt(1e18)
	// Enricher with an empty feed map: every price is stale.
	e, _ := New(Config{RPCURL: m.srv.URL, Clock: func() time.Time { return m.now }})
	er := ethTx(wallet, "0x2222222222222222222222222222222222222222", "1000000000000000000")
	if err := e.Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	if !er.PriceStale {
		t.Fatal("price should be stale with no feed")
	}
	if er.AmountUSD != nil {
		t.Fatalf("AmountUSD = %v, want nil on stale price", str(er.AmountUSD))
	}
	if er.PctOfBalance == nil { // pct still computes without a price
		t.Fatal("PctOfBalance should still be set without a price")
	}
}

func str(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestEnrichAgainstAnvil hits a real fork when ANVIL_RPC is set (the demo's
// setup), proving the ABI encode/decode works against a live node. Skipped in
// CI, which has no fork.
func TestEnrichAgainstAnvil(t *testing.T) {
	rpc := os.Getenv("ANVIL_RPC")
	if rpc == "" {
		t.Skip("set ANVIL_RPC to a Base fork to run the live balance/price check")
	}
	// Base mainnet ETH/USD Chainlink feed.
	e, err := New(Config{RPCURL: rpc, Feeds: map[string]string{NativeKey: "0x71041dddad3595f9ced3dccfbe3d1f4b0a16bb70"}})
	if err != nil {
		t.Fatal(err)
	}
	er := ethTx("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x2222222222222222222222222222222222222222", "1000000000000000000")
	if err := e.Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("live: amount_usd=%s pct=%s fee_usd=%s stale=%v\n", str(er.AmountUSD), str(er.PctOfBalance), str(er.MaxFeeUSD), er.PriceStale)
	if er.PriceStale {
		t.Fatal("the live ETH/USD feed should not be stale")
	}
}
