package enrich

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// PriceOracle reads USD prices from on-chain Chainlink aggregator feeds
// (CS-131) — no external API and no API key. A feed that has not updated within
// MaxStale, or that reports a non-positive answer, is treated as stale: the
// oracle returns stale=true and no price, so the enricher sets price_stale and
// policy escalates (never a $0 guess).
type PriceOracle struct {
	rpc     *RPC
	feeds   map[string]string // asset key (lowercase token addr, or "native") -> feed address
	maxAge  time.Duration
	ttl     time.Duration
	clock   func() time.Time
	mu      sync.Mutex
	cache   map[string]priceEntry
	feedDec map[string]int // feed address -> its decimals()
}

type priceEntry struct {
	price *big.Rat
	stale bool
	at    time.Time
}

// NativeKey is the price-feed key for the chain's native asset (ETH on Base).
const NativeKey = "native"

// NewPriceOracle returns an oracle over rpc. feeds maps an asset key to its
// Chainlink feed address; maxAge bounds a feed's updatedAt age (0 uses 1h, a
// safe bound for Base's ETH/USD heartbeat); ttl caches a read (0 uses 15s).
func NewPriceOracle(rpc *RPC, feeds map[string]string, maxAge, ttl time.Duration) *PriceOracle {
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	lower := make(map[string]string, len(feeds))
	for k, v := range feeds {
		lower[strings.ToLower(k)] = v
	}
	return &PriceOracle{rpc: rpc, feeds: lower, maxAge: maxAge, ttl: ttl, clock: time.Now,
		cache: map[string]priceEntry{}, feedDec: map[string]int{}}
}

// Price returns the USD price for an asset key (a lowercase token address, or
// NativeKey). stale is true when there is no usable price: no feed configured,
// an RPC failure, a non-positive answer, or an answer older than MaxAge. A
// stale result carries a nil price.
func (o *PriceOracle) Price(ctx context.Context, key string) (price *big.Rat, stale bool) {
	key = strings.ToLower(key)
	now := o.clock()
	o.mu.Lock()
	if e, ok := o.cache[key]; ok && now.Sub(e.at) < o.ttl {
		o.mu.Unlock()
		if e.stale {
			return nil, true
		}
		return new(big.Rat).Set(e.price), false
	}
	o.mu.Unlock()

	p, st := o.read(ctx, key, now)
	o.mu.Lock()
	o.cache[key] = priceEntry{price: p, stale: st, at: now}
	o.mu.Unlock()
	if st {
		return nil, true
	}
	return new(big.Rat).Set(p), false
}

func (o *PriceOracle) read(ctx context.Context, key string, now time.Time) (*big.Rat, bool) {
	feed, ok := o.feeds[key]
	if !ok {
		return nil, true // no feed for this asset: stale, policy escalates
	}
	ret, err := o.rpc.Call(ctx, feed, encodeCall(selLatestRoundData))
	if err != nil {
		return nil, true
	}
	// latestRoundData() -> (uint80 roundId, int256 answer, uint256 startedAt,
	// uint256 updatedAt, uint80 answeredInRound).
	answer, err := signedWord(ret, 1)
	if err != nil || answer.Sign() <= 0 {
		return nil, true
	}
	updatedAt, err := word(ret, 3)
	if err != nil || updatedAt.Sign() <= 0 {
		return nil, true
	}
	age := now.Sub(time.Unix(updatedAt.Int64(), 0))
	if age < 0 {
		age = -age
	}
	if age > o.maxAge {
		return nil, true // heartbeat missed: do not trust it
	}
	dec, err := o.decimals(ctx, feed)
	if err != nil {
		return nil, true
	}
	// price = answer / 10^dec
	return new(big.Rat).SetFrac(answer, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil)), false
}

func (o *PriceOracle) decimals(ctx context.Context, feed string) (int, error) {
	o.mu.Lock()
	if d, ok := o.feedDec[feed]; ok {
		o.mu.Unlock()
		return d, nil
	}
	o.mu.Unlock()
	ret, err := o.rpc.Call(ctx, feed, encodeCall(selDecimals))
	if err != nil {
		return 0, err
	}
	d, err := decodeUint(ret)
	if err != nil {
		return 0, fmt.Errorf("feed %s decimals: %w", feed, err)
	}
	o.mu.Lock()
	o.feedDec[feed] = int(d.Int64())
	o.mu.Unlock()
	return int(d.Int64()), nil
}
