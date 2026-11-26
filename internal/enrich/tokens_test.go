package enrich

import (
	"context"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/render"
)

const (
	wethToken    = "0x4200000000000000000000000000000000000006"
	hostileToken = "0x6666666666666666666666666666666666666666"
	brokenToken  = "0x7777777777777777777777777777777777777777"
)

// abiString ABI-encodes s as a string return value (offset, length, bytes).
func abiString(s string) string {
	b := []byte(s)
	pad := make([]byte, (32-len(b)%32)%32)
	return word32(big.NewInt(32)) + word32(big.NewInt(int64(len(b)))) + hex.EncodeToString(append(b, pad...))
}

func TestTokenAddrs(t *testing.T) {
	in := model.IntentSummary{Asset: &model.Asset{Address: strings.ToUpper(usdc[:2]) + usdc[2:]}, Calls: []model.IntentSummary{
		{Swap: &model.Swap{TokenIn: "", TokenOut: wethToken}},
		{Calls: []model.IntentSummary{{Asset: &model.Asset{Address: hostileToken}}, {Asset: &model.Asset{Address: usdc}}}},
	}}
	if got, want := TokenAddrs(in), []string{usdc, wethToken, hostileToken}; !slices.Equal(got, want) {
		t.Fatalf("TokenAddrs = %v, want %v", got, want)
	}
}

// TestEnrichTokenInfo (CS-143): every token the intent references, at any
// depth, gets on-chain decimals and a sanitized symbol; a failed or hostile
// read leaves the field unknown and never fails the request; reads are cached.
func TestEnrichTokenInfo(t *testing.T) {
	m := newMockNode(time.Unix(1_700_000_000, 0))
	m.ethWei, m.usdcUnits = big.NewInt(1e18), big.NewInt(100000_000000)
	chain := uint64(8453)
	newReq := func() model.EnrichedRequest {
		return model.EnrichedRequest{
			Request: model.ActionRequest{Action: model.Action{Kind: model.KindEVMTx, ChainID: &chain, From: wallet, To: usdc, ValueWei: "0", GasLimit: "60000", MaxFeePerGas: "200000000"}},
			Intent: model.IntentSummary{Kind: "transfer", Amount: "1000000", Destination: wallet, Asset: &model.Asset{Address: usdc}, Flags: []string{},
				Calls: []model.IntentSummary{
					{Kind: "transfer", Op: "swap_exact_in", Swap: &model.Swap{ExactIn: true, TokenIn: usdc, AmountIn: "1000000", TokenOut: wethToken, AmountOut: "1"}},
					{Kind: "approve", Asset: &model.Asset{Address: hostileToken}, Amount: "1"},
					{Kind: "approve", Asset: &model.Asset{Address: brokenToken}, Amount: "1"},
				}},
		}
	}
	e := m.enricher(t)
	er := newReq()
	if err := e.Enrich(context.Background(), &er); err != nil {
		t.Fatalf("a failed token read failed the request: %v", err)
	}
	d := func(t model.TokenInfo) int {
		if t.Decimals == nil {
			return -1
		}
		return *t.Decimals
	}
	for addr, want := range map[string]struct {
		sym string
		dec int
	}{
		usdc:         {"USDC", 6},
		wethToken:    {"WETH", 18},
		hostileToken: {"USDC" + strings.Repeat("X", render.MaxSymbolRunes-4) + "…", -1}, // bidi/newline stripped, capped; decimals 2^200 refused
		brokenToken:  {"", -1},
	} {
		got, ok := er.Tokens[addr]
		if !ok || got.Symbol != want.sym || d(got) != want.dec {
			t.Errorf("Tokens[%s] = %+v (decimals %d), want %q / %d", addr, got, d(got), want.sym, want.dec)
		}
	}
	text := render.Intent(er)
	if !strings.Contains(text, "0.000000000000000001 WETH") || !strings.Contains(text, "1 base units of token") || !strings.Contains(text, "(decimals unavailable)") {
		t.Errorf("rendering lacks on-chain token metadata:\n%s", text)
	}
	n := m.calls["eth_call:"+wethToken+":"+selSymbol]
	er = newReq()
	if err := e.Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	if m.calls["eth_call:"+wethToken+":"+selSymbol] != n {
		t.Error("symbol() was read again within the cache TTL")
	}
}

func TestDecodeString(t *testing.T) {
	for _, c := range []struct {
		ret  string
		want string
		err  bool
	}{
		{abiString("USDC"), "USDC", false},
		{hex.EncodeToString(append([]byte("MKR"), make([]byte, 29)...)), "MKR", false},
		{word32(big.NewInt(1<<40)) + word32(big.NewInt(4)), "", true}, // offset out of range
		{word32(big.NewInt(32)) + word32(big.NewInt(1000)), "", true}, // length out of range
		{"00", "", true},
	} {
		b, _ := hex.DecodeString(c.ret)
		got, err := decodeString(b)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("decodeString(%s…) = %q, %v; want %q, err=%v", c.ret[:min(16, len(c.ret))], got, err, c.want, c.err)
		}
	}
}
