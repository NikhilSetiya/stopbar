package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Feed is a Chainlink USD aggregator feed: its on-chain address and the maximum
// age of a reading before it is treated as stale — the feed's documented
// heartbeat. A per-feed bound is required because heartbeats differ by orders of
// magnitude (Base ETH/USD updates ~hourly; USDC/USD only every ~24h), so a
// single global bound would wrongly mark a healthy slow feed stale. A zero
// MaxAge falls back to the oracle's default bound.
type Feed struct {
	Address string
	MaxAge  time.Duration
}

// UnmarshalJSON accepts either a bare address string (heartbeat defaults to the
// oracle's bound) or an object {"address": "0x…", "max_age_sec": <seconds>}, so
// a world file can state each feed's documented heartbeat.
func (f *Feed) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		f.Address, f.MaxAge = s, 0
		return nil
	}
	var o struct {
		Address   string `json:"address"`
		MaxAgeSec int64  `json:"max_age_sec"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return fmt.Errorf("enrich: feed must be an address string or {address, max_age_sec}: %w", err)
	}
	if o.Address == "" {
		return errors.New("enrich: feed object needs an address")
	}
	f.Address, f.MaxAge = o.Address, time.Duration(o.MaxAgeSec)*time.Second
	return nil
}

// PriceOracle reads USD prices from on-chain Chainlink aggregator feeds
// (CS-131) — no external API and no API key. A feed that has not updated within
// its own heartbeat (Feed.MaxAge, else defaultAge), or that reports a
// non-positive answer, is treated as stale: the oracle returns stale=true and no
// price, so the enricher sets price_stale and policy escalates (never a $0 guess).
type PriceOracle struct {
	rpc        *RPC
	feeds      map[string]Feed // asset key (lowercase token addr, or "native") -> feed
	defaultAge time.Duration   // used when a feed sets no MaxAge
	ttl        time.Duration
	clock      func() time.Time
	mu         sync.Mutex
	cache      map[string]priceEntry
	feedDec    map[string]int // feed address -> its decimals()
}

type priceEntry struct {
	price *big.Rat
	stale bool
	at    time.Time
}

// NativeKey is the price-feed key for the chain's native asset (ETH on Base).
const NativeKey = "native"

// NewPriceOracle returns an oracle over rpc. feeds maps an asset key to its
// Chainlink feed (address + the feed's documented heartbeat); defaultAge bounds
// a feed that states no MaxAge (0 uses 1h, a safe bound for Base's ETH/USD
// heartbeat); ttl caches a read (0 uses 15s).
func NewPriceOracle(rpc *RPC, feeds map[string]Feed, defaultAge, ttl time.Duration) *PriceOracle {
	if defaultAge <= 0 {
		defaultAge = time.Hour
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	lower := make(map[string]Feed, len(feeds))
	for k, v := range feeds {
		lower[strings.ToLower(k)] = v
	}
	return &PriceOracle{rpc: rpc, feeds: lower, defaultAge: defaultAge, ttl: ttl, clock: time.Now,
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

// read fetches and validates a feed. _ is the (wall-clock) cache time, kept for
// the signature; staleness is judged against the chain clock, below.
func (o *PriceOracle) read(ctx context.Context, key string, _ time.Time) (*big.Rat, bool) {
	feed, ok := o.feeds[key]
	if !ok {
		return nil, true // no feed for this asset: stale, policy escalates
	}
	ret, err := o.rpc.Call(ctx, feed.Address, encodeCall(selLatestRoundData))
	if err != nil {
		return nil, true
	}
	// latestRoundData() -> (uint80 roundId, int256 answer, uint256 startedAt,
	// uint256 updatedAt, uint80 answeredInRound). The standard Chainlink
	// safety checks: a positive answer, a non-zero updatedAt, and a complete
	// round (answeredInRound >= roundId). Any failure is stale, never priced.
	roundID, err := word(ret, 0)
	if err != nil {
		return nil, true
	}
	answer, err := signedWord(ret, 1)
	if err != nil || answer.Sign() <= 0 { // zero or negative price
		return nil, true
	}
	updatedAt, err := word(ret, 3)
	if err != nil || updatedAt.Sign() <= 0 { // round not yet finalised
		return nil, true
	}
	answeredInRound, err := word(ret, 4)
	if err != nil || answeredInRound.Cmp(roundID) < 0 { // stale/incomplete round
		return nil, true
	}
	// Staleness against the CHAIN clock (the latest block's timestamp), so a
	// node forked at a past block does not make a fresh-at-that-block feed look
	// stale. A failure to read the block fails closed (stale).
	chainNow, err := o.rpc.BlockTimestamp(ctx)
	if err != nil {
		return nil, true
	}
	age := time.Duration(chainNow-updatedAt.Int64()) * time.Second
	if age < 0 {
		age = -age
	}
	maxAge := feed.MaxAge // this feed's documented heartbeat
	if maxAge <= 0 {
		maxAge = o.defaultAge
	}
	if age > maxAge {
		return nil, true // heartbeat missed: do not trust it
	}
	dec, err := o.decimals(ctx, feed.Address) // the feed's own decimals, never assumed
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
