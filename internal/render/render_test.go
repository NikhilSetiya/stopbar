package render

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// The embedded list is the published BIP-39 English list, byte for byte.
func TestWordlist(t *testing.T) {
	sum := sha256.Sum256([]byte(wordlistText))
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatalf("bip39-english.txt sha256 = %s, want the bitcoin/bips english.txt", got)
	}
	if len(words) != 2048 {
		t.Fatalf("%d words, want 2048", len(words))
	}
	seen := map[string]bool{}
	for _, w := range words {
		if seen[w[:min(4, len(w))]] {
			t.Fatalf("prefix of %q repeats: words must be unique in their first four letters", w)
		}
		seen[w[:min(4, len(w))]] = true
	}
}

func TestPhrase(t *testing.T) {
	for _, tc := range []struct {
		addr, want string
		err        bool
	}{
		// Frozen vectors (also reproduced in Python in docs/LLD.md §6.3):
		// changing the derivation changes what approvers compare.
		{addr: "0x9f30000000000000000000000000000000000c21", want: "quality warrior impose six whisper blame"},
		{addr: "0x9F30000000000000000000000000000000000C21", want: "quality warrior impose six whisper blame"},
		{addr: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", want: "guess daughter search shine spike mountain"},
		{addr: "0x9f3", err: true},
		{addr: "9f30000000000000000000000000000000000c21", err: true},
		{addr: "0x9f30000000000000000000000000000000000c2g", err: true},
		{addr: "0x9f30000000000000000000000000000000000c2100", err: true},
	} {
		got, err := Phrase(tc.addr)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("Phrase(%s) = %q, %v; want %q, err=%v", tc.addr, got, err, tc.want, tc.err)
		}
		if err == nil && len(strings.Fields(got)) != PhraseWords {
			t.Errorf("Phrase(%s) = %q: want %d words", tc.addr, got, PhraseWords)
		}
	}
	if got := Address("not-an-address"); got != "not-an-address" {
		t.Errorf("Address(non-address) = %q, want it unchanged", got)
	}
}

func mustPhrase(t *testing.T, a string) string {
	t.Helper()
	p, err := Phrase(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLookAlikePhrases is the acceptance check: addresses an attacker grinds
// to look like a real one (same first and last hex digits, one digit changed
// anywhere) all read clearly different. Each variant must differ from the
// target in at least 4 of the 6 words, and no two variants may share a phrase.
func TestLookAlikePhrases(t *testing.T) {
	targets := []string{
		"0x9f3a5c7e1b2d4f6a8c0e2b4d6f8a0c2e4b6d7c21",
		"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
		"0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
		"0x0000000000000000000000000000000000000000",
	}
	hexd := "0123456789abcdef"
	for _, target := range targets {
		tp := strings.Fields(mustPhrase(t, target))
		var variants []string
		// One hex digit changed at every position, to every other value.
		for i := 2; i < 42; i++ {
			for _, c := range hexd {
				if byte(c) != target[i] {
					variants = append(variants, target[:i]+string(c)+target[i+1:])
				}
			}
		}
		// Poisoning-style: first 4 and last 4 hex digits kept, the middle 32
		// replaced (deterministic pseudo-random middles).
		for n := 0; n < 2000; n++ {
			mid := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", target, n)))
			variants = append(variants, target[:6]+hex.EncodeToString(mid[:16])+target[38:])
		}
		seen := map[string]string{strings.Join(tp, " "): target}
		for _, v := range variants {
			vp := strings.Fields(mustPhrase(t, v))
			same := 0
			for i := range vp {
				if vp[i] == tp[i] {
					same++
				}
			}
			if same > 2 {
				t.Errorf("look-alike %s shares %d of 6 words with %s", v, same, target)
			}
			if prev, dup := seen[strings.Join(vp, " ")]; dup {
				t.Errorf("phrase collision: %s and %s", v, prev)
			}
			seen[strings.Join(vp, " ")] = v
			// The shortened form alone is identical for the poisoning
			// variants: the phrase is what tells them apart.
			if Address(v) == Address(target) {
				t.Errorf("Address(%s) == Address(%s)", v, target)
			}
		}
		if mustPhrase(t, "0x"+strings.ToUpper(target[2:])) != strings.Join(tp, " ") {
			t.Errorf("case changed the phrase of %s", target)
		}
	}
}

func ptr(s string) *string { return &s }

func u64(v uint64) *uint64 { return &v }

const (
	from    = "0x2222222222222222222222222222222222222222"
	usdc    = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
	dest    = "0x9f3a5c7e1b2d4f6a8c0e2b4d6f8a0c2e4b6d7c21"
	poison  = "0x9f3a000000000000000000000000000000007c21"
	router  = "0x2626664c2603336e57b271c5c0b26f421741e481"
	weth    = "0x4200000000000000000000000000000000000006"
	nope    = "0x1111111111111111111111111111111111111111"
	hashHex = "sha256:115a07fa95f9351e06647d316e88a53bbdbdd1928cf495214742e519fd8fc601"
)

func evm(to string) model.ActionRequest {
	return model.ActionRequest{Action: model.Action{Kind: model.KindEVMTx, ChainID: u64(8453), From: from, To: to}}
}

func usdcAsset() *model.Asset { return &model.Asset{ChainID: 8453, Address: usdc} }

func dec(d int) *int { return &d }

// usdcTok is the enrichment for usdc; weth and "nope" cover a known output
// token and one whose decimals() could not be read.
var (
	usdcTok = map[string]model.TokenInfo{usdc: {Symbol: "USDC", Decimals: dec(6)}}
	allToks = map[string]model.TokenInfo{usdc: {Symbol: "USDC", Decimals: dec(6)}, weth: {Symbol: "WETH", Decimals: dec(18)}, nope: {}}
)

// TestIntentGolden snapshots the rendering per kind. Run with -update to
// rewrite testdata/*.golden, then review the diff.
func TestIntentGolden(t *testing.T) {
	tool := "send_email\nValue: $0.00"
	cases := map[string]model.EnrichedRequest{
		"native_transfer": {Request: evm(dest), AmountUSD: ptr("3125.5"), MaxFeeUSD: ptr("0.004"),
			Intent: model.IntentSummary{Kind: "transfer", Op: "native_transfer", Amount: "1250000000000000000", Destination: dest, Flags: []string{},
				Human: "Send 1250000000000000000 wei (native) to " + dest, PayloadHash: hashHex}},
		"erc20_transfer": {Request: evm(usdc), Tokens: usdcTok, AmountUSD: ptr("1500250.249"), MaxFeeUSD: ptr("0.42"),
			Intent: model.IntentSummary{Kind: "transfer", Op: "erc20_transfer", Asset: usdcAsset(), Amount: "1500250249000", Destination: dest,
				Flags: []string{"new_destination"}, Human: "Transfer 1500250249000 units of token " + usdc + " to " + dest, PayloadHash: hashHex}},
		"erc20_transfer_poisoned": {Request: evm(usdc), Tokens: usdcTok, AmountUSD: ptr("1500.25"), MaxFeeUSD: ptr("0.42"),
			Intent: model.IntentSummary{Kind: "transfer", Op: "erc20_transfer", Asset: usdcAsset(), Amount: "1500250000", Destination: poison,
				Flags: []string{"new_destination", "similar_destination"}, Human: "Transfer 1500250000 units of token " + usdc + " to " + poison, PayloadHash: hashHex}},
		"price_unavailable": {Request: evm(usdc), PriceStale: true, Tokens: map[string]model.TokenInfo{usdc: {Decimals: dec(6)}},
			Intent: model.IntentSummary{Kind: "transfer", Op: "erc20_transfer", Asset: usdcAsset(), Amount: "2000000",
				Destination: dest, Flags: []string{}, Human: "Transfer 2000000 units of token " + usdc + " to " + dest, PayloadHash: hashHex}},
		"unknown_decimals": {Request: evm(usdc), PriceStale: true,
			Intent: model.IntentSummary{Kind: "transfer", Op: "erc20_transfer", Asset: &model.Asset{ChainID: 8453, Address: usdc}, Amount: "2000000",
				Destination: dest, Flags: []string{}, Human: "Transfer 2000000 units of token " + usdc + " to " + dest, PayloadHash: hashHex}},
		"unlimited_approval": {Request: evm(usdc), Tokens: usdcTok, AmountUSD: ptr("0"), MaxFeeUSD: ptr("0.1"),
			Intent: model.IntentSummary{Kind: "approve", Op: "erc20_approve", Asset: usdcAsset(), Amount: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
				Destination: dest, Flags: []string{"unlimited_approval"}, Human: "Allow " + dest + " to spend 1157…935 units of token " + usdc, PayloadHash: hashHex}},
		"bounded_approval": {Request: evm(usdc), Tokens: usdcTok, AmountUSD: ptr("0"), ApprovalUSD: ptr("50"), MaxFeeUSD: ptr("0.1"),
			Intent: model.IntentSummary{Kind: "approve", Op: "erc20_approve", Asset: usdcAsset(), Amount: "50000000",
				Destination: router, Flags: []string{}, Human: "Allow " + router + " to spend 50000000 units of token " + usdc, PayloadHash: hashHex}},
		"set_approval_for_all": {Request: evm(usdc), AmountUSD: ptr("0"), MaxFeeUSD: ptr("0.1"),
			Intent: model.IntentSummary{Kind: "approve", Op: "set_approval_for_all", Asset: &model.Asset{ChainID: 8453, Address: usdc}, Destination: dest,
				Flags: []string{"unlimited_approval"}, Human: "Let " + dest + " move every token in " + usdc, PayloadHash: hashHex}},
		"swap_min_out_zero": {Request: evm(router), Tokens: usdcTok, AmountUSD: ptr("1000"), MaxFeeUSD: ptr("0.2"),
			Intent: model.IntentSummary{Kind: "transfer", Op: "swap_exact_in", Asset: usdcAsset(), Amount: "1000000000", Destination: from,
				Flags: []string{"min_out_zero"}, Swap: &model.Swap{ExactIn: true, TokenIn: usdc, AmountIn: "1000000000", TokenOut: "", AmountOut: "0"},
				Human: "Swap 1000000000 units of token " + usdc + " for token  (min out 0), sent to " + from + " — accepts ANY output (no slippage protection)", PayloadHash: hashHex}},
		"safe_delegatecall": {Request: evm(dest), MaxFeeUSD: ptr("1.5"),
			Intent: model.IntentSummary{Kind: "contract_call", Op: "safe_exec", Flags: []string{"delegatecall"},
				Human: "Safe " + dest + " executes: DELEGATECALL (runs foreign code as the Safe): Call contract " + poison + " with undecoded calldata", PayloadHash: hashHex}},
		// Every token inside a batch is shown with its decimals and symbol;
		// one whose decimals() failed says so and shows raw base units.
		"multicall_tokens": {Request: evm(router), Tokens: allToks, AmountUSD: ptr("1000"), MaxFeeUSD: ptr("0.3"),
			Intent: model.IntentSummary{Kind: "transfer", Op: "multicall", Target: router, Asset: usdcAsset(), Amount: "1000000000", Destination: from,
				Flags: []string{}, Human: "multicall of 3 call(s): …", PayloadHash: hashHex, Calls: []model.IntentSummary{
					{Kind: "transfer", Op: "swap_exact_in", Asset: usdcAsset(), Amount: "1000000000", Destination: from, Flags: []string{},
						Swap: &model.Swap{ExactIn: true, TokenIn: usdc, AmountIn: "1000000000", TokenOut: weth, AmountOut: "250000000000000000"}},
					{Kind: "approve", Op: "erc20_approve", Asset: &model.Asset{ChainID: 8453, Address: nope}, Amount: "5000", Destination: router, Flags: []string{}},
					{Kind: "contract_call", Op: "safe_exec", Target: dest, Flags: []string{}, Calls: []model.IntentSummary{
						{Kind: "transfer", Op: "erc20_transfer", Asset: &model.Asset{ChainID: 8453, Address: weth}, Amount: "1500000000000000000", Destination: poison, Flags: []string{}},
						{Kind: "contract_call", Op: "unknown", Target: poison, Flags: []string{"unknown_call"}, Human: "Call contract " + poison + " with undecoded calldata"},
					}},
				}}},
		"tool_call_injection": {Request: model.ActionRequest{Action: model.Action{Kind: model.KindToolCall, Tool: &tool}},
			Intent: model.IntentSummary{Kind: "tool_call", Flags: []string{"untrusted_web"}, Human: "Call tool " + tool + "\u202e with 1 argument(s)", PayloadHash: hashHex}},
	}
	for name, er := range cases {
		t.Run(name, func(t *testing.T) {
			got := Intent(er)
			path := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if got != string(want) {
				t.Errorf("rendering changed:\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

// Properties every rendering keeps, whatever the template.
func TestIntentProperties(t *testing.T) {
	er := model.EnrichedRequest{Request: evm(usdc), PriceStale: true,
		Intent: model.IntentSummary{Kind: "transfer", Op: "erc20_transfer", Asset: usdcAsset(), Amount: "1", Destination: dest, Flags: []string{}, Human: "x " + dest, PayloadHash: hashHex}}
	got := Intent(er)
	for _, want := range []string{"Value: price unavailable", "Max network fee: price unavailable", "Payload hash: " + hashHex, mustPhrase(t, dest)} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "$0") {
		t.Errorf("a missing price rendered as $0:\n%s", got)
	}
	if strings.Contains(got, dest) {
		t.Errorf("full address left unrendered (no phrase):\n%s", got)
	}
}

func TestFormatting(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{usd(ptr("1234567.891")), "$1,234,567.89"},
		{usd(ptr("0")), "$0.00"},
		{usd(ptr("0.001")), "< $0.01"},
		{usd(ptr("-1")), "price unavailable"},
		{usd(nil), "price unavailable"},
		{renderer{chain: 1}.amount("1000000000000000001", ""), "1.000000000000000001 ETH"},
		{renderer{chain: 137}.amount("5", ""), "0.000000000000000005 POL"},
		{renderer{chain: 8453, tokens: usdcTok}.amount("1500000", usdc), "1.5 USDC " + usdc},
		{renderer{chain: 8453, tokens: usdcTok}.amount("1500000", strings.ToUpper(usdc[:2])+usdc[2:]), "1.5 USDC 0X" + usdc[2:]},
		{renderer{chain: 8453}.amount("1500000", usdc), "1,500,000 base units of token " + usdc + " (decimals unavailable)"},
		{renderer{chain: 8453, tokens: map[string]model.TokenInfo{usdc: {Symbol: "USDC"}}}.amount("15", usdc), "15 base units of USDC " + usdc + " (decimals unavailable)"},
		{renderer{chain: 8453, tokens: map[string]model.TokenInfo{usdc: {Decimals: dec(256)}}}.amount("15", usdc), "15 base units of token " + usdc + " (decimals unavailable)"},
		{renderer{chain: 8453, tokens: map[string]model.TokenInfo{usdc: {Decimals: dec(0)}}}.amount("15", usdc), "15 token " + usdc},
		{renderer{chain: 1}.amount("-1", ""), "-1 (unparsable amount)"},
		{SanitizeSymbol("US\u202eDC\n\x00"), "USDC"},
		{SanitizeSymbol("  ok  "), "ok"},
		{SanitizeSymbol("\xff\xfeUSD"), "USD"},
		{SanitizeSymbol(strings.Repeat("A", 40)), strings.Repeat("A", 16) + "…"},
		{SanitizeSymbol("0x9f3a5c7e1b2d4f6a8c0e2b4d6f8a0c2e4b6d7c21"), "0x9f3a5c7e1b2d4f…"},
		{group("1234"), "1,234"},
		{group("123"), "123"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}
