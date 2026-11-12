package enrich

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"time"
)

// BalanceProvider reads native and ERC-20 balances from the chain (CS-132),
// with a short cache so a burst of requests for the same wallet does not hammer
// the RPC. A read failure is returned, not guessed; the enricher decides what a
// missing balance means for policy.
type BalanceProvider struct {
	rpc   *RPC
	ttl   time.Duration
	clock func() time.Time

	mu    sync.Mutex
	cache map[string]balanceEntry
}

type balanceEntry struct {
	val *big.Int
	at  time.Time
}

// NewBalanceProvider returns a provider over rpc. ttl bounds how long a balance
// is cached (0 uses 10s, the LLD §19 budget).
func NewBalanceProvider(rpc *RPC, ttl time.Duration) *BalanceProvider {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &BalanceProvider{rpc: rpc, ttl: ttl, clock: time.Now, cache: map[string]balanceEntry{}}
}

// Balance returns the raw balance (wei for native, token units for ERC-20) of
// wallet. token is the ERC-20 contract address, or "" for the native asset.
func (b *BalanceProvider) Balance(ctx context.Context, wallet, token string) (*big.Int, error) {
	key := strings.ToLower(wallet) + "|" + strings.ToLower(token)
	now := b.clock()
	b.mu.Lock()
	if e, ok := b.cache[key]; ok && now.Sub(e.at) < b.ttl {
		b.mu.Unlock()
		return new(big.Int).Set(e.val), nil
	}
	b.mu.Unlock()

	val, err := b.read(ctx, wallet, token)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.cache[key] = balanceEntry{val: new(big.Int).Set(val), at: now}
	b.mu.Unlock()
	return val, nil
}

func (b *BalanceProvider) read(ctx context.Context, wallet, token string) (*big.Int, error) {
	if token == "" {
		return b.rpc.BalanceAt(ctx, wallet)
	}
	data, err := encodeAddressCall(selBalanceOf, wallet)
	if err != nil {
		return nil, err
	}
	ret, err := b.rpc.Call(ctx, token, data)
	if err != nil {
		return nil, err
	}
	return decodeUint(ret)
}

// Decimals reads a token's decimals() from the chain, cached under the token
// address. Native ETH is 18 and never queried.
func (b *BalanceProvider) Decimals(ctx context.Context, token string) (int, error) {
	key := "decimals|" + strings.ToLower(token)
	now := b.clock()
	b.mu.Lock()
	if e, ok := b.cache[key]; ok && now.Sub(e.at) < b.ttl {
		b.mu.Unlock()
		return int(e.val.Int64()), nil
	}
	b.mu.Unlock()

	ret, err := b.rpc.Call(ctx, token, encodeCall(selDecimals))
	if err != nil {
		return 0, err
	}
	d, err := decodeUint(ret)
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	b.cache[key] = balanceEntry{val: new(big.Int).Set(d), at: now}
	b.mu.Unlock()
	return int(d.Int64()), nil
}
