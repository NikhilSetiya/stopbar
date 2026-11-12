package enrich

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Config wires a ChainEnricher.
type Config struct {
	RPCURL string // Ethereum JSON-RPC endpoint (the Base node or an Anvil fork)
	// Feeds maps an asset key — a lowercase ERC-20 address, or NativeKey — to its
	// Chainlink USD feed (address + the feed's documented heartbeat). An asset
	// with no feed prices as stale.
	Feeds map[string]Feed
	// KnownDestinations is the allowlist used for Destination.Known /
	// SimilarToKnown until the CS-133 registry replaces it.
	KnownDestinations []string
	RPCTimeout        time.Duration
	PriceMaxAge       time.Duration // default bound for a feed that sets no max_age (default 1h)
	PriceTTL          time.Duration // price cache (default 15s)
	BalanceTTL        time.Duration // balance cache (default 10s)
	Clock             func() time.Time
}

// ChainEnricher fills the policy context from the chain (CS-131/132): USD
// amount, fee and approval value from Chainlink feeds, pct-of-balance from
// native/ERC-20 balance reads, and destination facts from the allowlist. It
// implements engine.Enricher.
type ChainEnricher struct {
	prices *PriceOracle
	bals   *BalanceProvider
	known  []string
}

// New builds a ChainEnricher from cfg.
func New(cfg Config) (*ChainEnricher, error) {
	if cfg.RPCURL == "" {
		return nil, errors.New("enrich: RPCURL is required")
	}
	rpc := NewRPC(cfg.RPCURL, cfg.RPCTimeout)
	prices := NewPriceOracle(rpc, cfg.Feeds, cfg.PriceMaxAge, cfg.PriceTTL)
	bals := NewBalanceProvider(rpc, cfg.BalanceTTL)
	if cfg.Clock != nil {
		prices.clock = cfg.Clock
		bals.clock = cfg.Clock
	}
	known := make([]string, len(cfg.KnownDestinations))
	for i, k := range cfg.KnownDestinations {
		known[i] = strings.ToLower(k)
	}
	return &ChainEnricher{prices: prices, bals: bals, known: known}, nil
}

// Enrich reads prices and balances for the request's asset and fills the policy
// context. A missing or stale price is marked (price_stale), never guessed; a
// balance read failure is returned so the engine fails closed.
func (e *ChainEnricher) Enrich(ctx context.Context, er *model.EnrichedRequest) error {
	if er.Request.Action.Kind == model.KindToolCall {
		return nil // no prices or balances for tool calls
	}
	// Several outflows in one tx can't be priced as a single amount; reading the
	// empty amount as $0 would slip under every cap. (CS-131 could price each
	// outflow and sum them; for now this fails closed, as the devstub did.)
	if slices.Contains(er.Intent.Flags, "multi_transfer") {
		return errors.New("enrich: several outflows in one transaction can't be priced yet")
	}

	wallet := er.Request.Action.From
	priceKey, decimals := NativeKey, 18
	var tokenAddr string
	if er.Intent.Asset != nil {
		tokenAddr = strings.ToLower(er.Intent.Asset.Address)
		priceKey = tokenAddr
		d, err := e.bals.Decimals(ctx, tokenAddr)
		if err != nil {
			return fmt.Errorf("enrich: token %s decimals: %w", tokenAddr, err)
		}
		decimals = d
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)

	raw, ok := new(big.Rat).SetString(er.Intent.Amount)
	if !ok || er.Intent.Kind == "approve" {
		raw = new(big.Rat) // contract calls and approvals move no funds when made
	}
	tokens := new(big.Rat).Quo(raw, new(big.Rat).SetInt(scale))
	// amount_tokens is the raw amount in token units — known from the decoded tx
	// and the asset's decimals, with no price. It backs a price-independent cap
	// so an unpriced transfer is never allowed unchecked (stale-price-amount-cap).
	er.AmountTokens = decimalString(tokens)

	// Price the moved asset.
	if price, stale := e.prices.Price(ctx, priceKey); stale {
		er.PriceStale = true
	} else {
		er.AmountUSD = decimalString(new(big.Rat).Mul(tokens, price))
		if er.Intent.Kind == "approve" && !slices.Contains(er.Intent.Flags, "unlimited_approval") {
			if amt, ok := new(big.Rat).SetString(er.Intent.Amount); ok {
				er.ApprovalUSD = decimalString(new(big.Rat).Mul(new(big.Rat).Quo(amt, new(big.Rat).SetInt(scale)), price))
			}
		}
	}

	// Fees are paid in the native asset whatever is being moved.
	if fee := maxFeeWei(er.Request.Action); fee != nil {
		if price, stale := e.prices.Price(ctx, NativeKey); stale {
			er.PriceStale = true
		} else {
			eth := new(big.Rat).SetFrac(fee, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
			er.MaxFeeUSD = decimalString(eth.Mul(eth, price))
		}
	}

	// pct_of_balance from the wallet's balance of the moved asset.
	bal, err := e.bals.Balance(ctx, wallet, tokenAddr)
	if err != nil {
		return fmt.Errorf("enrich: balance of %s: %w", wallet, err)
	}
	if bal.Sign() > 0 {
		balTokens := new(big.Rat).SetFrac(bal, scale)
		er.PctOfBalance = decimalString(new(big.Rat).Quo(tokens, balTokens))
	}

	// Destination facts (allowlist; CS-133 adds the real registry + similarity).
	dest := strings.ToLower(er.Intent.Destination)
	for _, k := range e.known {
		switch {
		case k == dest:
			er.Destination.Known = true
		case len(k) == 42 && len(dest) == 42 && k[:6] == dest[:6] && k[38:] == dest[38:]:
			er.Destination.SimilarToKnown = true
		}
	}
	return nil
}

// maxFeeWei is gas_limit × max_fee_per_gas.
func maxFeeWei(a model.Action) *big.Int {
	g, ok1 := new(big.Int).SetString(a.GasLimit, 10)
	f, ok2 := new(big.Int).SetString(a.MaxFeePerGas, 10)
	if !ok1 || !ok2 {
		return nil
	}
	return g.Mul(g, f)
}

// decimalString renders a non-negative r with up to 18 fractional digits,
// rounding up, so downstream conversion never sees less than the truth. (Kept
// identical to internal/devstub's rendering so the chain enricher and the stub
// produce the same strings for the same values.)
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
