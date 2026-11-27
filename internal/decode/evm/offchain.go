package evm

// Off-chain signature requests (CS-514, LLD §6.1a): EIP-712 typed data
// (eth_signTypedData_v4) and EIP-191 personal_sign. A signed Permit, Permit2
// permit or Seaport order is as good as the on-chain approval or transfer it
// authorises, so it decodes into the same intent with the same flags.
//
// The decoding is structural: no keccak. A typed-data payload is matched to
// a known primary type by its declared type definitions, which must equal
// the canonical ones exactly; the EIP-712 digest is computed only by the
// signer (internal/signer), from the same bound bytes.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Off-chain flags (LLD §6.2).
const (
	// FlagLongExpiry: a signed approval stays usable for more than
	// LongExpiry (or forever): a standing grant, not a one-off.
	FlagLongExpiry = "long_expiry"
	// FlagZeroConsideration: a Seaport order gives assets away and pays the
	// signer nothing.
	FlagZeroConsideration = "zero_consideration"
)

// LongExpiry is how far ahead a signed approval may expire before it is
// flagged long_expiry. Uniswap's Permit2 default is 30 days.
const LongExpiry = 31 * 24 * time.Hour

// kindSign is the policy action for an off-chain message that is neither an
// approval nor an order (personal_sign, unknown typed data).
const kindSign = "sign_message"

// Permit2 is the canonical Permit2 contract (same address on every chain).
const Permit2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

type fields = []model.TypedField

// Canonical type definitions. A payload whose primary type has one of these
// names must declare exactly these members (and referenced types), or it is a
// decode error: a look-alike "PermitSingle" must not be read as Permit2.
var (
	eip2612Permit  = fields{{Name: "owner", Type: "address"}, {Name: "spender", Type: "address"}, {Name: "value", Type: "uint256"}, {Name: "nonce", Type: "uint256"}, {Name: "deadline", Type: "uint256"}}
	daiPermit      = fields{{Name: "holder", Type: "address"}, {Name: "spender", Type: "address"}, {Name: "nonce", Type: "uint256"}, {Name: "expiry", Type: "uint256"}, {Name: "allowed", Type: "bool"}}
	permitDetails  = fields{{Name: "token", Type: "address"}, {Name: "amount", Type: "uint160"}, {Name: "expiration", Type: "uint48"}, {Name: "nonce", Type: "uint48"}}
	permitSingle   = fields{{Name: "details", Type: "PermitDetails"}, {Name: "spender", Type: "address"}, {Name: "sigDeadline", Type: "uint256"}}
	permitBatch    = fields{{Name: "details", Type: "PermitDetails[]"}, {Name: "spender", Type: "address"}, {Name: "sigDeadline", Type: "uint256"}}
	seaportOrder   = fields{{Name: "offerer", Type: "address"}, {Name: "zone", Type: "address"}, {Name: "offer", Type: "OfferItem[]"}, {Name: "consideration", Type: "ConsiderationItem[]"}, {Name: "orderType", Type: "uint8"}, {Name: "startTime", Type: "uint256"}, {Name: "endTime", Type: "uint256"}, {Name: "zoneHash", Type: "bytes32"}, {Name: "salt", Type: "uint256"}, {Name: "conduitKey", Type: "bytes32"}, {Name: "counter", Type: "uint256"}}
	seaportOffer   = fields{{Name: "itemType", Type: "uint8"}, {Name: "token", Type: "address"}, {Name: "identifierOrCriteria", Type: "uint256"}, {Name: "startAmount", Type: "uint256"}, {Name: "endAmount", Type: "uint256"}}
	seaportConsid  = append(slices.Clone(seaportOffer), model.TypedField{Name: "recipient", Type: "address"})
	maxUint256     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	errNonStandard = errors.New("declares a known primary type with non-standard members")
)

// offchain decodes an evm_typed_data or evm_personal_sign action.
func (dc Decoder) offchain(a model.Action) (model.IntentSummary, error) {
	if a.ChainID == nil {
		return model.IntentSummary{}, errors.New("evm: chain_id missing")
	}
	d := &decoder{chain: *a.ChainID, from: strings.ToLower(a.From)}
	if a.Kind == model.KindEVMPersonalSign {
		return personalSign(a.Message)
	}
	td := a.TypedData
	if td == nil {
		return model.IntentSummary{}, errors.New("evm: typed_data missing")
	}
	if p := td.Problems(*a.ChainID); len(p) > 0 {
		return model.IntentSummary{}, fmt.Errorf("evm: typed data: %s", strings.Join(p, "; "))
	}
	now := time.Now
	if dc.Now != nil {
		now = dc.Now
	}
	in, err := d.typed(td, now())
	if err != nil {
		return model.IntentSummary{}, fmt.Errorf("evm: typed data %s: %w", td.PrimaryType, err)
	}
	if in.Flags == nil {
		in.Flags = []string{}
	}
	in.Flags = union(in.Flags)
	return in, nil
}

// reader reads validated typed-data values, keeping the first error.
type reader struct{ err error }

func (r *reader) fail(k string) {
	if r.err == nil {
		r.err = fmt.Errorf("member %q missing or ill-typed", k)
	}
}

func (r *reader) addr(m map[string]any, k string) string {
	s, ok := m[k].(string)
	if !ok || len(s) != 42 {
		r.fail(k)
	}
	return strings.ToLower(s)
}

func (r *reader) num(m map[string]any, k string) *big.Int {
	n, err := model.TypedInt(m[k])
	if err != nil {
		r.fail(k)
		return new(big.Int)
	}
	return n
}

func (r *reader) obj(m map[string]any, k string) map[string]any {
	o, ok := m[k].(map[string]any)
	if !ok {
		r.fail(k)
	}
	return o
}

func (r *reader) list(m map[string]any, k string) []map[string]any {
	arr, ok := m[k].([]any)
	if !ok {
		r.fail(k)
	}
	out := make([]map[string]any, 0, len(arr))
	for _, el := range arr {
		o, ok := el.(map[string]any)
		if !ok {
			r.fail(k)
		}
		out = append(out, o)
	}
	return out
}

func declares(td *model.TypedData, want map[string]fields) bool {
	for name, f := range want {
		if !slices.Equal(td.Types[name], f) {
			return false
		}
	}
	return true
}

func (d *decoder) typed(td *model.TypedData, now time.Time) (model.IntentSummary, error) {
	r := &reader{}
	m := td.Message
	vc, _ := td.Domain["verifyingContract"].(string)
	vc = strings.ToLower(vc)
	where := fmt.Sprintf("on chain %d", d.chain)
	if vc != "" {
		where = fmt.Sprintf("for contract %s on chain %d", vc, d.chain)
	}
	signer := func(k string) {
		if who := r.addr(m, k); r.err == nil && who != d.from {
			r.err = fmt.Errorf("%s %s is not the signer %s", k, who, d.from)
		}
	}
	var in model.IntentSummary
	switch td.PrimaryType {
	case "Permit":
		if vc == "" {
			return in, errors.New("a permit needs domain.verifyingContract (the token)")
		}
		switch {
		case declares(td, map[string]fields{"Permit": eip2612Permit}):
			signer("owner")
			spender, value, deadline := r.addr(m, "spender"), r.num(m, "value"), r.num(m, "deadline")
			in = model.IntentSummary{Kind: kindApprove, Op: "erc2612_permit_signature", Asset: d.asset(vc), Amount: value.String(), Destination: spender,
				Human: fmt.Sprintf("Sign an EIP-2612 permit letting %s spend %s units of token %s (signature usable until %s)", spender, value, vc, when(deadline))}
			if isMax(value, 255) {
				in.Flags = append(in.Flags, FlagUnlimitedApproval)
			}
			d.expire(&in, deadline, false, now)
		case declares(td, map[string]fields{"Permit": daiPermit}):
			signer("holder")
			spender, expiry := r.addr(m, "spender"), r.num(m, "expiry")
			allowed, ok := m["allowed"].(bool)
			if !ok {
				r.fail("allowed")
			}
			if !allowed {
				in = model.IntentSummary{Kind: kindApprove, Op: "dai_permit_revoke_signature", Asset: d.asset(vc), Amount: "0", Destination: spender,
					Human: fmt.Sprintf("Sign a DAI-style permit revoking %s's allowance on token %s", spender, vc)}
				break
			}
			in = model.IntentSummary{Kind: kindApprove, Op: "dai_permit_signature", Asset: d.asset(vc), Amount: maxUint256.String(), Destination: spender,
				Flags: []string{FlagUnlimitedApproval}, Human: fmt.Sprintf("Sign a DAI-style permit letting %s spend all of token %s (until %s)", spender, vc, when(expiry))}
			d.expire(&in, expiry, expiry.Sign() == 0, now) // DAI: expiry 0 never expires
		default:
			return in, errNonStandard
		}

	case "PermitSingle":
		if !declares(td, map[string]fields{"PermitSingle": permitSingle, "PermitDetails": permitDetails}) {
			return in, errNonStandard
		}
		det := r.obj(m, "details")
		spender := r.addr(m, "spender")
		token, amt, exp := r.addr(det, "token"), r.num(det, "amount"), r.num(det, "expiration")
		in = d.permit2("permit2_permit_signature", token, spender, amt)
		in.Human = fmt.Sprintf("Sign a Permit2 permit letting %s spend %s units of token %s (allowance until %s)%s", spender, amt, token, when(exp), notPermit2(vc))
		d.expire(&in, exp, false, now)

	case "PermitBatch":
		if !declares(td, map[string]fields{"PermitBatch": permitBatch, "PermitDetails": permitDetails}) {
			return in, errNonStandard
		}
		spender := r.addr(m, "spender")
		latest := new(big.Int)
		var calls []model.IntentSummary
		for _, det := range r.list(m, "details") {
			token, amt, exp := r.addr(det, "token"), r.num(det, "amount"), r.num(det, "expiration")
			c := d.permit2("permit2_permit_signature", token, spender, amt)
			c.Human += fmt.Sprintf(" (allowance until %s)", when(exp))
			calls = append(calls, c)
			if exp.Cmp(latest) > 0 {
				latest = exp
			}
		}
		in = batch("permit2_permit_batch_signature", vc, calls)
		in.Kind = kindApprove // every member is an approval; never permitted as a plain contract call
		in.Target = ""
		in.Human = "Sign a Permit2 batch permit" + notPermit2(vc) + ": " + strings.Join(humans(calls), "; ")
		d.expire(&in, latest, false, now)

	case "OrderComponents":
		if !declares(td, map[string]fields{"OrderComponents": seaportOrder, "OfferItem": seaportOffer, "ConsiderationItem": seaportConsid}) {
			return in, errNonStandard
		}
		signer("offerer")
		in = d.seaport(r, m, vc)

	default:
		in = model.IntentSummary{Kind: kindSign, Op: "typed_data", Flags: []string{FlagUnknownCall},
			Human: fmt.Sprintf("Sign %s typed data %s (domain %s): %s", td.PrimaryType, where, render(td.Domain["name"]), render(m))}
	}
	if r.err != nil {
		return model.IntentSummary{}, r.err
	}
	return in, nil
}

// seaport decodes a Seaport OrderComponents: what the signer offers, and
// what the order pays back to the signer and to others.
func (d *decoder) seaport(r *reader, m map[string]any, vc string) model.IntentSummary {
	offerer, end := r.addr(m, "offerer"), r.num(m, "endTime")
	in := model.IntentSummary{Kind: kindTransfer, Op: "seaport_order", Amount: "0", Expiry: end.String()}
	var gives, gets, others []string
	offers := r.list(m, "offer")
	for _, it := range offers {
		typ, token, id, amt := seaportItem(r, it)
		gives = append(gives, itemText(typ, token, id, amt))
		if len(offers) == 1 {
			in.Amount = amt.String()
			if typ.Sign() != 0 {
				in.Asset = d.asset(token)
			}
		}
	}
	paid := false
	for _, it := range r.list(m, "consideration") {
		typ, token, id, amt := seaportItem(r, it)
		to := r.addr(it, "recipient")
		if to == offerer {
			paid = paid || amt.Sign() > 0
			gets = append(gets, itemText(typ, token, id, amt))
		} else {
			others = append(others, itemText(typ, token, id, amt)+" to "+to)
		}
	}
	if len(offers) > 1 {
		in.Flags = append(in.Flags, FlagMultiTransfer)
		in.Amount = ""
	}
	if len(offers) > 0 && !paid {
		in.Flags = append(in.Flags, FlagZeroConsideration)
		gets = append(gets, "NOTHING")
	}
	in.Human = fmt.Sprintf("Sign a Seaport order (contract %s) giving %s; you receive %s", vc, list(gives), list(gets))
	if len(others) > 0 {
		in.Human += "; others receive " + strings.Join(others, ", ")
	}
	in.Human += "; fillable by anyone until " + when(end)
	return in
}

// seaportItem reads an item; the amount is the larger of start and end, so a
// descending or ascending price is shown at its worst for the signer's offer.
func seaportItem(r *reader, it map[string]any) (typ *big.Int, token string, id, amt *big.Int) {
	typ, token, id = r.num(it, "itemType"), r.addr(it, "token"), r.num(it, "identifierOrCriteria")
	start, end := r.num(it, "startAmount"), r.num(it, "endAmount")
	if typ.Cmp(big.NewInt(5)) > 0 {
		r.fail("itemType")
	}
	amt = start
	if end.Cmp(start) > 0 {
		amt = end
	}
	return typ, token, id, amt
}

func itemText(typ *big.Int, token string, id, amt *big.Int) string {
	switch typ.Int64() {
	case 0:
		return fmt.Sprintf("%s wei (native)", amt)
	case 1:
		return fmt.Sprintf("%s units of token %s", amt, token)
	case 2, 3:
		return fmt.Sprintf("%s of token ID %s in %s", amt, id, token)
	default:
		return fmt.Sprintf("%s of ANY token in %s matching criteria", amt, token)
	}
}

// expire sets the intent's expiry and flags a grant usable beyond LongExpiry.
func (d *decoder) expire(in *model.IntentSummary, exp *big.Int, never bool, now time.Time) {
	in.Expiry = exp.String()
	limit := big.NewInt(now.Add(LongExpiry).Unix())
	if never || exp.Cmp(limit) > 0 {
		in.Flags = append(in.Flags, FlagLongExpiry)
	}
	if never {
		in.Human += " (never expires)"
	}
}

func notPermit2(vc string) string {
	if vc == Permit2 {
		return ""
	}
	return fmt.Sprintf(" via %s (NOT the canonical Permit2 contract)", vc)
}

func when(unix *big.Int) string {
	if !unix.IsInt64() || unix.Int64() > 253402300799 { // after 9999-12-31
		return "unix " + unix.String() + " (effectively never)"
	}
	return time.Unix(unix.Int64(), 0).UTC().Format(time.RFC3339)
}

func humans(calls []model.IntentSummary) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Human
	}
	return out
}

func list(items []string) string {
	if len(items) == 0 {
		return "nothing"
	}
	return strings.Join(items, ", ")
}

const maxRender = 500

// render shows a typed-data value as compact JSON, truncated.
func render(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "(unrenderable)"
	}
	return truncate(string(b))
}

func truncate(s string) string {
	if utf8.RuneCountInString(s) <= maxRender {
		return s
	}
	return string([]rune(s)[:maxRender]) + "…"
}

// personalSign decodes an EIP-191 personal_sign message: readable text is
// shown; anything else (a hash, a serialized transaction) is opaque, since
// what signing it authorises can't be known.
func personalSign(msgHex string) (model.IntentSummary, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(msgHex, "0x"))
	if err != nil || len(b) == 0 || !strings.HasPrefix(msgHex, "0x") {
		return model.IntentSummary{}, errors.New("evm: personal_sign message is not 0x-prefixed hex")
	}
	if text := string(b); utf8.Valid(b) && !strings.ContainsFunc(text, func(c rune) bool {
		return !unicode.IsPrint(c) && c != '\n' && c != '\t' && c != '\r'
	}) {
		return model.IntentSummary{Kind: kindSign, Op: "personal_sign", Flags: []string{},
			Human: fmt.Sprintf("Sign the message %q", truncate(text))}, nil
	}
	return model.IntentSummary{Kind: kindSign, Op: "personal_sign_raw", Flags: []string{FlagOpaque},
		Human: fmt.Sprintf("Sign %d raw bytes %s (not readable text: could be a hash or a transaction)", len(b), truncate(strings.ToLower(msgHex)))}, nil
}
