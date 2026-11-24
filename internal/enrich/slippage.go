package enrich

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// FlagExcessiveSlippage marks a swap whose limit gives away more than the
// tenant's max slippage at oracle prices (LLD §6.2, CS-145).
const FlagExcessiveSlippage = "excessive_slippage"

// DefaultMaxSlippage is the tenant max slippage when none is configured (3%).
const DefaultMaxSlippage = "0.03"

// ParseMaxSlippage reads a max slippage fraction ("" is the default). It must
// be in [0, 1).
func ParseMaxSlippage(s string) (*big.Rat, error) {
	if s == "" {
		s = DefaultMaxSlippage
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 || r.Cmp(big.NewRat(1, 1)) >= 0 {
		return nil, fmt.Errorf("max_slippage %q: want a decimal fraction in [0, 1), e.g. \"0.03\"", s)
	}
	return r, nil
}

// Quote prices one asset: USD per whole token and the token's decimals.
// Token "" is the native asset. ok=false means no fresh price.
type Quote func(ctx context.Context, token string) (usd *big.Rat, decimals int, ok bool, err error)

// CheckSlippage flags excessive_slippage when any swap in the intent, at any
// depth, would accept an outcome worth less than (1 − maxSlippage) of what
// it gives at oracle prices: an exact-in swap's minimum output, or an
// exact-out swap's output against its maximum input. Wrapped native is
// priced as native. A swap that can't be priced marks the price stale, so
// policy escalates rather than trusting an unchecked limit.
func CheckSlippage(ctx context.Context, er *model.EnrichedRequest, maxSlippage *big.Rat, quote Quote) error {
	var chain uint64
	if er.Request.Action.ChainID != nil {
		chain = *er.Request.Action.ChainID
	}
	keep := new(big.Rat).Sub(big.NewRat(1, 1), maxSlippage)
	value := func(token, amount string) (*big.Rat, bool, error) {
		if strings.EqualFold(token, evm.WrappedNative[chain]) {
			token = ""
		}
		raw, ok := new(big.Rat).SetString(amount)
		if !ok {
			return nil, false, fmt.Errorf("swap amount %q is not a number", amount)
		}
		p, dec, ok, err := quote(ctx, strings.ToLower(token))
		if err != nil || !ok {
			return nil, false, err
		}
		scale := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil))
		return raw.Quo(raw, scale).Mul(raw, p), true, nil
	}
	var walk func(in model.IntentSummary) error
	walk = func(in model.IntentSummary) error {
		if s := in.Swap; s != nil {
			give, ok1, err := value(s.TokenIn, s.AmountIn)
			if err != nil {
				return err
			}
			get, ok2, err := value(s.TokenOut, s.AmountOut)
			if err != nil {
				return err
			}
			switch {
			case !ok1 || !ok2:
				er.PriceStale = true
			case get.Cmp(new(big.Rat).Mul(give, keep)) < 0:
				addFlag(er, FlagExcessiveSlippage)
			}
		}
		for _, c := range in.Calls {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(er.Intent)
}
