// Package render turns an enriched request into the plain-language text an
// approver reads before signing over its payload_hash (CS-143, FR-IR-3, LLD
// §6.3). Every address is shown shortened (0x9f30…0c21) with a 6-word
// checksum phrase derived from the full address, so a look-alike address
// (address poisoning: same leading and trailing hex digits) reads clearly
// different.
//
// Stdlib only: it is what a human approves.
package render

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// The BIP-39 English wordlist (2048 words, 11 bits each, unique in their
// first four letters), verbatim from bitcoin/bips; a test pins its sha256.
//
//go:embed bip39-english.txt
var wordlistText string

var words = strings.Fields(wordlistText)

// phraseDomain separates the checksum hash from every other sha256 Stopbar
// computes over an address.
const phraseDomain = "stopbar-address-checksum-v1\x00"

// PhraseWords is the number of words in a checksum phrase: 6 × 11 = 66 bits.
const PhraseWords = 6

var reAddr = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// Phrase returns the checksum phrase of an EVM address: the first 66 bits of
// sha256(phraseDomain || the 20 address bytes), as 6 BIP-39 words. Case
// (EIP-55) does not change it. Any other change to the address gives an
// unrelated phrase, so matching the visible hex digits does not help an
// attacker match the phrase (docs/LLD.md §6.3 has the work factor).
func Phrase(addr string) (string, error) {
	if !reAddr.MatchString(addr) {
		return "", fmt.Errorf("render: %q is not a 0x-prefixed 20-byte address", addr)
	}
	raw, _ := hex.DecodeString(addr[2:]) // validated above
	sum := sha256.Sum256(append([]byte(phraseDomain), raw...))
	out := make([]string, PhraseWords)
	for i := range out {
		out[i] = words[bits11(sum[:], i)]
	}
	return strings.Join(out, " "), nil
}

// bits11 returns the i-th 11-bit big-endian group of b.
func bits11(b []byte, i int) int {
	v := 0
	for j := 0; j < 11; j++ {
		bit := i*11 + j
		v = v<<1 | int(b[bit/8]>>(7-bit%8)&1)
	}
	return v
}

// Address renders addr as "0x9f30…0c21 [six checksum words]". Anything that is
// not an address is returned unchanged.
func Address(addr string) string {
	p, err := Phrase(addr)
	if err != nil {
		return addr
	}
	a := strings.ToLower(addr)
	return a[:6] + "…" + a[38:] + " [" + p + "]"
}

// addrInText finds whole addresses inside text (not prefixes of longer hex).
var addrInText = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)

// Intent renders what an approver is asked to sign. The text is built from
// the decoded intent and the enrichment, never from the requester's claims:
//
//	headline (what moves where), value in USD, max network fee in USD,
//	sender and chain, flags, every inner call (batches, Safe, multicall),
//	the decoder's raw description, payload hash.
//
// A missing price reads "price unavailable", never $0 (LLD §3, CS-131). A
// token whose decimals could not be read shows raw base units and says
// "decimals unavailable", never a guessed number.
func Intent(er model.EnrichedRequest) string {
	in, a := er.Intent, er.Request.Action
	r := renderer{to: a.To, tokens: er.Tokens}
	if a.ChainID != nil {
		r.chain = *a.ChainID
	}
	var b strings.Builder
	line := func(format string, args ...any) { _, _ = fmt.Fprintf(&b, format+"\n", args...) }

	if a.Kind == model.KindToolCall {
		line("%s", clean(in.Human))
	} else {
		line("%s", r.headline(in))
		if v := value(er); v != "" {
			line("Value: %s", v)
		}
		line("Max network fee: %s", usd(er.MaxFeeUSD))
		line("From: %s on %s", a.From, chainName(r.chain))
	}
	flags := "none"
	if len(in.Flags) > 0 {
		flags = strings.Join(in.Flags, ", ")
	}
	line("Flags: %s", flags)
	if len(in.Calls) > 0 {
		line("Calls:")
		r.calls(&b, in.Calls, "  ")
	}
	if a.Kind != model.KindToolCall {
		line("Decoder: %s", clean(in.Human))
	}
	line("Payload hash: %s", in.PayloadHash)
	return addrInText.ReplaceAllStringFunc(b.String(), Address)
}

type renderer struct {
	chain  uint64
	to     string                     // the transaction's target
	tokens map[string]model.TokenInfo // enrichment, keyed by lowercase address
}

// calls writes one line per inner call, nested batches indented.
func (r renderer) calls(b *strings.Builder, cs []model.IntentSummary, indent string) {
	for _, c := range cs {
		if len(c.Calls) > 0 {
			_, _ = fmt.Fprintf(b, "%s- %s %s, %d call(s):\n", indent, c.Op, c.Target, len(c.Calls))
			r.calls(b, c.Calls, indent+"  ")
			continue
		}
		s := clean(c.Human) // contract calls: the decoder's description
		switch {
		case c.Swap != nil:
			s = r.swapLine(*c.Swap, c.Destination)
		case c.Kind == "transfer" || c.Kind == "approve":
			s = r.headline(c)
		}
		_, _ = fmt.Fprintf(b, "%s- %s\n", indent, s)
	}
}

// headline is the one-line summary, by policy action (kind).
func (r renderer) headline(in model.IntentSummary) string {
	token := ""
	if in.Asset != nil {
		token = in.Asset.Address
	}
	switch in.Kind {
	case "transfer":
		if s := onlySwap(in); s != nil {
			return r.swapLine(*s, in.Destination)
		}
		if in.Amount == "" {
			return fmt.Sprintf("Move several tokens of %s to %s", r.tokenName(token), in.Destination)
		}
		return fmt.Sprintf("Send %s to %s", r.amount(in.Amount, token), in.Destination)
	case "approve":
		switch {
		case in.Op == "set_approval_for_all":
			return fmt.Sprintf("Let %s move EVERY token in %s", in.Destination, r.tokenName(token))
		case in.Op == "revoke_approval_for_all":
			return fmt.Sprintf("Revoke %s as operator of every token in %s", in.Destination, r.tokenName(token))
		case slices.Contains(in.Flags, "unlimited_approval"):
			return fmt.Sprintf("Allow %s to spend an UNLIMITED amount of %s", in.Destination, r.tokenName(token))
		}
		return fmt.Sprintf("Allow %s to spend %s", in.Destination, r.amount(in.Amount, token))
	}
	return fmt.Sprintf("Call contract %s (%s)", r.to, in.Op)
}

// onlySwap returns the swap a transfer intent is, directly or as the single
// swap inside a batch.
func onlySwap(in model.IntentSummary) *model.Swap {
	var found []*model.Swap
	var walk func(model.IntentSummary)
	walk = func(c model.IntentSummary) {
		if c.Swap != nil {
			found = append(found, c.Swap)
		}
		for _, cc := range c.Calls {
			walk(cc)
		}
	}
	walk(in)
	if len(found) != 1 {
		return nil
	}
	return found[0]
}

func (r renderer) swapLine(s model.Swap, recipient string) string {
	give, get := r.amount(s.AmountIn, s.TokenIn), r.amount(s.AmountOut, s.TokenOut)
	if s.ExactIn {
		if s.AmountOut == "0" {
			return fmt.Sprintf("Swap %s for ANY amount of %s (no minimum: accepts nothing back), to %s", give, r.tokenName(s.TokenOut), recipient)
		}
		return fmt.Sprintf("Swap %s for at least %s, to %s", give, get, recipient)
	}
	return fmt.Sprintf("Swap at most %s for %s, to %s", give, get, recipient)
}

// value is the line an approver reads as "how much is at stake".
func value(er model.EnrichedRequest) string {
	in := er.Intent
	switch {
	case in.Kind == "approve" && (slices.Contains(in.Flags, "unlimited_approval") || in.Op == "set_approval_for_all"):
		return "UNLIMITED (the spender can take the whole balance)"
	case in.Op == "revoke_approval_for_all" || (in.Kind == "approve" && in.Amount == "0"):
		return "none (revokes access)"
	case in.Kind == "approve":
		return usd(er.ApprovalUSD)
	case in.Amount == "":
		return ""
	}
	return usd(er.AmountUSD)
}

// usd formats a decimal USD string, or "price unavailable" when there is none.
func usd(s *string) string {
	if s == nil {
		return "price unavailable"
	}
	r, ok := new(big.Rat).SetString(*s)
	if !ok || r.Sign() < 0 {
		return "price unavailable"
	}
	if r.Sign() > 0 && r.Cmp(big.NewRat(1, 100)) < 0 {
		return "< $0.01"
	}
	f := r.FloatString(2)
	i := strings.IndexByte(f, '.')
	return "$" + group(f[:i]) + f[i:]
}

// MaxDecimals bounds the decimals a token may claim. ERC-20 decimals() is a
// uint8; anything larger is a broken or hostile token and is not used.
const MaxDecimals = 255

// amount formats raw base units of token ("" = native) with its decimals and
// symbol from the enrichment, or as raw base units with "decimals
// unavailable" when the decimals could not be read.
func (r renderer) amount(raw, token string) string {
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok || n.Sign() < 0 {
		return raw + " (unparsable amount)"
	}
	if token == "" {
		return units(n, 18) + " " + nativeSymbol(r.chain)
	}
	if t, ok := r.tokens[strings.ToLower(token)]; ok && t.Decimals != nil && *t.Decimals >= 0 && *t.Decimals <= MaxDecimals {
		return units(n, *t.Decimals) + " " + r.tokenName(token)
	}
	return group(n.String()) + " base units of " + r.tokenName(token) + " (decimals unavailable)"
}

// units is n / 10^decimals as an exact decimal, grouped, trailing zeros cut.
func units(n *big.Int, decimals int) string {
	if decimals <= 0 {
		return group(n.String())
	}
	ip, fp := new(big.Int).QuoRem(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil), new(big.Int))
	s := group(ip.String())
	if frac := strings.TrimRight(fmt.Sprintf("%0*s", decimals, fp.String()), "0"); frac != "" {
		s += "." + frac
	}
	return s
}

// tokenName is "SYMBOL 0x…" when the symbol is known, else "token 0x…"; ""
// is the chain's native asset.
func (r renderer) tokenName(token string) string {
	if token == "" {
		return nativeSymbol(r.chain)
	}
	if sym := SanitizeSymbol(r.tokens[strings.ToLower(token)].Symbol); sym != "" {
		return sym + " " + token
	}
	return "token " + token
}

// MaxSymbolRunes caps a displayed token symbol. symbol() is whatever the
// token contract returns (attacker-controlled); the cap also keeps it far
// shorter than an address, so it cannot carry a fake one.
const MaxSymbolRunes = 16

// SanitizeSymbol makes an on-chain symbol() safe to show: invalid UTF-8,
// control, format (bidi overrides, zero-width) and separator characters
// are dropped, surrounding space trimmed, and the result capped at
// MaxSymbolRunes.
func SanitizeSymbol(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	if rs := []rune(s); len(rs) > MaxSymbolRunes {
		s = string(rs[:MaxSymbolRunes]) + "…"
	}
	return s
}

// group inserts thousands separators into a run of digits.
func group(d string) string {
	if len(d) <= 3 {
		return d
	}
	var b strings.Builder
	for i, c := range d {
		if i > 0 && (len(d)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func nativeSymbol(chain uint64) string {
	switch chain {
	case 56:
		return "BNB"
	case 137:
		return "POL"
	}
	return "ETH"
}

var chainNames = map[uint64]string{
	1: "ethereum", 10: "optimism", 56: "bnb", 137: "polygon", 8453: "base",
	84532: "base-sepolia", 42161: "arbitrum", 11155111: "sepolia", 31337: "anvil",
}

func chainName(id uint64) string {
	if n, ok := chainNames[id]; ok {
		return n + " (chain " + strconv.FormatUint(id, 10) + ")"
	}
	return "chain " + strconv.FormatUint(id, 10)
}

// clean folds control and format characters (newlines, bidi overrides,
// zero-width) to spaces, so text that came from a request (a tool name)
// cannot forge extra lines of the rendering or reorder what is shown.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
}
