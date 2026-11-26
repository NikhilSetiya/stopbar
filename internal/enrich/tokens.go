package enrich

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/render"
)

// MaxTokenLookups bounds the tokens read per request, so a batch naming many
// tokens cannot stretch the enrichment toward its stage timeout. Tokens past
// the bound render as raw units with "decimals unavailable".
const MaxTokenLookups = 16

// TokenAddrs lists every token address the intent references at any depth
// (assets, swap in/out tokens), lowercase, deduplicated, in first-seen order.
// "" (native) is skipped.
func TokenAddrs(in model.IntentSummary) []string {
	var out []string
	add := func(a string) {
		if a = strings.ToLower(a); a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	var walk func(model.IntentSummary)
	walk = func(c model.IntentSummary) {
		if c.Asset != nil {
			add(c.Asset.Address)
		}
		if c.Swap != nil {
			add(c.Swap.TokenIn)
			add(c.Swap.TokenOut)
		}
		for _, cc := range c.Calls {
			walk(cc)
		}
	}
	walk(in)
	return out
}

// tokenInfo reads decimals() and symbol() of every token the intent
// references, for the approver's rendering (CS-143). A failed read leaves
// that field unknown; it never fails the request. The reads get half the
// time left on ctx, so a slow RPC cannot push the enricher past its stage
// timeout.
func (e *ChainEnricher) tokenInfo(ctx context.Context, in model.IntentSummary) map[string]model.TokenInfo {
	addrs := TokenAddrs(in)
	if len(addrs) == 0 {
		return nil
	}
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Until(dl)/2)
		defer cancel()
	}
	out := make(map[string]model.TokenInfo, len(addrs))
	for i, a := range addrs {
		var t model.TokenInfo
		if i < MaxTokenLookups && ctx.Err() == nil {
			if d, err := e.bals.Decimals(ctx, a); err == nil {
				t.Decimals = &d
			}
			if s, err := e.bals.Symbol(ctx, a); err == nil {
				t.Symbol = render.SanitizeSymbol(s)
			}
		}
		out[a] = t
	}
	return out
}
