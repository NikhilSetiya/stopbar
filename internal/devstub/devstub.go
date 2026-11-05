// Package devstub provides stand-in engine components so stopbard can run the
// real gateway, engine and policy bundle end to end before the production
// components exist. NOT FOR PRODUCTION: stopbard enables them only with
// -dev-world and logs a warning.
//
// Each stub names the task that replaces it.
package devstub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// MaxFeeWei is gas_limit × max_fee_per_gas: the most the tx can pay in fees.
// (The decoder stub that lived here was replaced by internal/decode/evm,
// CS-141/142.)
func MaxFeeWei(a model.Action) *big.Int {
	g, _ := new(big.Int).SetString(a.GasLimit, 10)
	f, _ := new(big.Int).SetString(a.MaxFeePerGas, 10)
	if g == nil || f == nil {
		return nil
	}
	return g.Mul(g, f)
}

// ---- enricher (replaced by CS-131/132/133) ----

// World is a static view of prices, balances and known destinations, in the
// shape of a corpus entry's `setup` (corpus/schema.json). Velocity comes from
// the real limiter, which is configured from Limits.
type World struct {
	KnownDestinations []string          `json:"known_destinations"`
	Balances          map[string]string `json:"balances"`   // symbol -> whole tokens
	PricesUSD         map[string]string `json:"prices_usd"` // symbol -> USD
	Tokens            map[string]Token  `json:"tokens"`     // contract address -> token
	PriceStale        bool              `json:"price_stale"`
	Limits            []limiter.Rule    `json:"limits"` // empty: DefaultLimits
	// LimitsDisabled runs the limiter with no caps (velocity is still
	// tracked). For experiments where the limiter is not under test, such as
	// the AgentDojo pilot, whose pre-registered arm is policy only.
	LimitsDisabled bool `json:"limits_disabled"`
	// PriorOutflowUSD1h is rejected: prior spend must be real reservations
	// (a corpus `requests` sequence), not a number the enricher invents.
	PriorOutflowUSD1h string `json:"prior_outflow_usd_1h"`
}

// DefaultLimits are LLD §17's example caps, used when a world sets none.
var DefaultLimits = []limiter.Rule{
	{Scope: limiter.ScopeWallet, Window: "1h", MaxUSD: "5000", MaxCount: 50},
	{Scope: limiter.ScopeTenant, Window: "1h", MaxUSD: "20000"},
}

// Token describes an ERC-20 contract. The native asset is symbol "ETH", 18 decimals.
type Token struct {
	Symbol   string `json:"symbol"`
	Decimals int    `json:"decimals"`
}

// LoadWorld reads a World from a JSON file.
func LoadWorld(path string) (*World, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w World
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("devstub: world %s: %w", path, err)
	}
	if w.PriorOutflowUSD1h != "" {
		return nil, fmt.Errorf("devstub: world %s: prior_outflow_usd_1h is not supported; model prior spend as a `requests` sequence", path)
	}
	if w.LimitsDisabled && len(w.Limits) > 0 {
		return nil, fmt.Errorf("devstub: world %s sets both limits and limits_disabled", path)
	}
	if len(w.Limits) == 0 && !w.LimitsDisabled {
		w.Limits = DefaultLimits
	}
	return &w, nil
}

// Enrich fills amount, balance share and destination facts. A
// missing price or balance is left unset (and the price marked stale), so the
// policy layer fails closed rather than evaluating a guess.
func (w *World) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	if er.Request.Action.Kind == model.KindToolCall {
		return nil // no prices or balances for tool calls; taint comes from policy.SessionTaint
	}
	// Several outflows (a batch moving more than one asset or amount) can't be
	// priced as one amount; reading the empty amount as $0 would slip under
	// every cap. CS-131 prices each outflow and sums them.
	if slices.Contains(er.Intent.Flags, "multi_transfer") {
		return errors.New("devstub: several outflows in one transaction can't be priced yet (CS-131)")
	}
	symbol, decimals := "ETH", 18
	if er.Intent.Asset != nil {
		t, ok := w.Tokens[strings.ToLower(er.Intent.Asset.Address)]
		if !ok {
			return fmt.Errorf("devstub: unknown token %s", er.Intent.Asset.Address)
		}
		symbol, decimals = t.Symbol, t.Decimals
	}
	raw, ok := new(big.Rat).SetString(er.Intent.Amount)
	if !ok || er.Intent.Kind == "approve" {
		// Contract calls carry no amount, and an approval moves no funds when
		// it is made: its risk is in the decoder's flags (unlimited_approval),
		// not in spend.
		raw = new(big.Rat)
	}
	tokens := new(big.Rat).Quo(raw, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)))

	er.PriceStale = w.PriceStale
	if p, ok := ratOf(w.PricesUSD[symbol]); ok && !w.PriceStale {
		er.AmountUSD = decimalString(new(big.Rat).Mul(tokens, p))
		// A bounded approval's value, so a policy can cap what a spender may
		// move. Unlimited approvals get none (the flag carries their risk).
		if er.Intent.Kind == "approve" && !slices.Contains(er.Intent.Flags, "unlimited_approval") {
			if amt, ok := new(big.Rat).SetString(er.Intent.Amount); ok {
				scale := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
				er.ApprovalUSD = decimalString(new(big.Rat).Mul(new(big.Rat).Quo(amt, scale), p))
			}
		}
	} else {
		er.PriceStale = true
	}
	// Fees are paid in the native asset whatever is being moved.
	if fee := MaxFeeWei(er.Request.Action); fee != nil {
		if p, ok := ratOf(w.PricesUSD["ETH"]); ok && !w.PriceStale {
			eth := new(big.Rat).SetFrac(fee, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
			er.MaxFeeUSD = decimalString(eth.Mul(eth, p))
		} else {
			er.PriceStale = true
		}
	}
	if bal, ok := ratOf(w.Balances[symbol]); ok && bal.Sign() > 0 {
		er.PctOfBalance = decimalString(new(big.Rat).Quo(tokens, bal))
	}
	dest := strings.ToLower(er.Intent.Destination)
	for _, k := range w.KnownDestinations {
		k = strings.ToLower(k)
		switch {
		case k == dest:
			er.Destination.Known = true
		case len(k) == 42 && len(dest) == 42 && k[:6] == dest[:6] && k[38:] == dest[38:]:
			er.Destination.SimilarToKnown = true // same first/last 4 hex digits (CS-133 does this properly)
		}
	}
	return nil
}

func ratOf(s string) (*big.Rat, bool) {
	if s == "" {
		return nil, false
	}
	return new(big.Rat).SetString(s)
}

// decimalString renders a non-negative r with up to 18 fractional digits,
// rounding up, so downstream conversion never sees less than the truth.
func decimalString(r *big.Rat) *string {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	num := new(big.Int).Mul(r.Num(), scale)
	q, m := new(big.Int).QuoRem(num, r.Denom(), new(big.Int))
	if m.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	ip, fp := new(big.Int).QuoRem(q, scale, new(big.Int))
	s := ip.String()
	if frac := strings.TrimRight(fmt.Sprintf("%018s", fp.String()), "0"); frac != "" {
		s += "." + frac
	}
	return &s
}
