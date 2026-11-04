// Package limiter bounds loss: sliding-window caps on USD value, transaction
// count and raw token units per scope key, with reserve → commit/release
// accounting so concurrent requests cannot race past a cap (CS-121/122,
// LLD §7).
//
// Guarantees:
//   - All or nothing. One Reserve checks every applicable cap on every key
//     (tenant, agent, wallet, wallet+asset, destination) before it changes
//     anything. A single mutex serialises Reserve, Commit and Release, so the
//     usage of every key is within its caps at every instant.
//   - No floats. USD is integer micro-dollars in big.Int, rounded up from
//     decimal strings. Token amounts are raw units in big.Int.
//   - Durable before visible. Every state change is written to the Store
//     before it is applied in memory. If the write fails, nothing changes.
//     Restarting a process does not reset its caps.
//   - Time comes only from the injected clock. Expiry is derived from it on
//     every call, so there are no timers or janitor goroutine to race.
//
// Sliding windows use 60 sub-buckets each, counted conservatively: a spend
// stays in a window for up to one sub-bucket (window/60) longer than the
// window itself, and never for less.
package limiter

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Scope is what a cap is keyed on.
type Scope string

const (
	ScopeTenant      Scope = "tenant"
	ScopeAgent       Scope = "agent"
	ScopeWallet      Scope = "wallet"
	ScopeWalletAsset Scope = "wallet+asset"
	ScopeDestination Scope = "destination"
)

var scopes = []Scope{ScopeTenant, ScopeAgent, ScopeWallet, ScopeWalletAsset, ScopeDestination}

// Windows are the sliding windows every key is tracked over.
var Windows = []time.Duration{time.Minute, time.Hour, 24 * time.Hour}

const subBuckets = 60

// Errors. Cap and circuit errors wrap the engine's domain errors.
var (
	ErrUnpriced             = errors.New("limiter: a USD cap applies but the request has no USD amount")
	ErrUnknownReservation   = engine.ErrUnknownReservation
	ErrReservationExpired   = engine.ErrReservationExpired
	ErrDuplicateReservation = errors.New("limiter: request ID was already used for a finished reservation")
	ErrAlreadyCommitted     = errors.New("limiter: reservation is already committed")
)

// Rule is one cap. At least one of MaxUSD, MaxCount and MaxUnits must be set.
type Rule struct {
	Scope    Scope  `json:"scope"`
	Window   string `json:"window"`              // "1m", "1h" or "24h"
	MaxUSD   string `json:"max_usd,omitempty"`   // decimal string, ≤ 6 fractional digits
	MaxCount int64  `json:"max_count,omitempty"` // transactions
	MaxUnits string `json:"max_units,omitempty"` // raw token units; wallet+asset only
	// UnknownDestinationsOnly applies a destination rule only when the
	// destination is not known (salami draining, FR-LIM-2a).
	UnknownDestinationsOnly bool `json:"unknown_destinations_only,omitempty"`
}

type rule struct {
	Rule
	window   int // index into Windows
	maxUSD   *big.Int
	maxUnits *big.Int
}

// Config wires a Limiter.
type Config struct {
	Rules []Rule
	Store Store // nil: in-memory only (tests, dev)
	Clock func() time.Time
}

// Limiter implements engine.Limiter and engine.Enricher (velocity context).
type Limiter struct {
	mu    sync.Mutex
	rules []rule
	store Store
	clock func() time.Time
	recs  map[string]*entry
	usage map[string]*keyUsage
	// Sweeping is proportional to what lapsed, not to what is retained:
	// live reservations sit in a heap by expiry, and every record in a
	// queue by creation time (retention pruning).
	expiry expiryHeap
	byTime []*entry
	// afterChange, when set (tests only), runs with the lock held after every
	// change to usage, so an invariant can be checked in every state the
	// limiter ever passes through.
	afterChange func(now time.Time)
}

// amount is one request's contribution. usd is nil when unpriced.
type amount struct {
	usd   *big.Int
	count int64
	units *big.Int
}

type entry struct {
	Record
	amt     amount
	counted bool // currently included in usage
}

type keyUsage struct {
	buckets [3]map[int64]*bucket // per window: sub-bucket index -> totals
}

type bucket struct {
	usd   *big.Int
	count int64
	units *big.Int
}

// New validates the rules and rebuilds state from the store.
func New(cfg Config) (*Limiter, error) {
	l := &Limiter{store: cfg.Store, clock: cfg.Clock, recs: map[string]*entry{}, usage: map[string]*keyUsage{}}
	if l.store == nil {
		l.store = MemStore{}
	}
	if l.clock == nil {
		l.clock = time.Now
	}
	for i, r := range cfg.Rules {
		cr, err := compile(r)
		if err != nil {
			return nil, fmt.Errorf("limiter: rule %d: %w", i, err)
		}
		l.rules = append(l.rules, cr)
	}
	recs, err := l.store.Load()
	if err != nil {
		return nil, fmt.Errorf("limiter: loading state: %w", err)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	now := l.clock()
	for _, r := range recs {
		e, err := fromRecord(r)
		if err != nil {
			return nil, fmt.Errorf("limiter: record %q: %w", r.ID, err)
		}
		l.track(e)
		if e.State == StateCommitted || (e.State == StateReserved && now.Before(e.Expires)) {
			l.add(e)
		}
	}
	l.sweep(now)
	return l, nil
}

func compile(r Rule) (rule, error) {
	cr := rule{Rule: r, window: -1}
	valid := false
	for _, s := range scopes {
		valid = valid || r.Scope == s
	}
	if !valid {
		return cr, fmt.Errorf("unknown scope %q", r.Scope)
	}
	d, err := time.ParseDuration(r.Window)
	if err != nil {
		return cr, fmt.Errorf("window: %w", err)
	}
	for i, w := range Windows {
		if w == d {
			cr.window = i
		}
	}
	if cr.window < 0 {
		return cr, fmt.Errorf("window %s: must be one of 1m, 1h, 24h", r.Window)
	}
	if r.MaxUSD != "" {
		if cr.maxUSD, err = parseUSD(r.MaxUSD, false); err != nil {
			return cr, fmt.Errorf("max_usd: %w", err)
		}
	}
	if r.MaxUnits != "" {
		if r.Scope != ScopeWalletAsset {
			return cr, errors.New("max_units is only meaningful on wallet+asset scope")
		}
		v, ok := new(big.Int).SetString(r.MaxUnits, 10)
		if !ok || v.Sign() < 0 {
			return cr, fmt.Errorf("max_units %q: not a non-negative integer", r.MaxUnits)
		}
		cr.maxUnits = v
	}
	if r.MaxCount < 0 {
		return cr, errors.New("max_count must be ≥ 0")
	}
	if cr.maxUSD == nil && cr.maxUnits == nil && r.MaxCount == 0 {
		return cr, errors.New("rule sets no cap")
	}
	if r.UnknownDestinationsOnly && r.Scope != ScopeDestination {
		return cr, errors.New("unknown_destinations_only is only meaningful on destination scope")
	}
	return cr, nil
}

var reUSD = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// parseUSD converts a decimal string to micro-dollars. Amounts round up
// (never under-count spend). Caps must be exact.
func parseUSD(s string, roundUp bool) (*big.Int, error) {
	if !reUSD.MatchString(s) {
		return nil, fmt.Errorf("%q is not a non-negative decimal string", s)
	}
	r, _ := new(big.Rat).SetString(s)
	r.Mul(r, big.NewRat(1_000_000, 1))
	q, m := new(big.Int).QuoRem(r.Num(), r.Denom(), new(big.Int))
	if m.Sign() != 0 {
		if !roundUp {
			return nil, fmt.Errorf("%q has more than 6 fractional digits", s)
		}
		q.Add(q, big.NewInt(1))
	}
	return q, nil
}

// keys returns the scope key for each scope. Components are quoted, so no
// requester-chosen value (tenant, agent ID) can make two keys collide.
//
// Agent and tenant come from the request and are only as trustworthy as its
// authentication (CS-103). Wallet scopes are bound to the signing address.
func keys(er model.EnrichedRequest) map[Scope]string {
	a := er.Request.Action
	chain := uint64(0)
	if a.ChainID != nil {
		chain = *a.ChainID
	}
	k := func(parts ...string) string {
		q := make([]string, len(parts))
		for i, p := range parts {
			q[i] = strconv.Quote(p)
		}
		return strings.Join(q, "/")
	}
	t, c := er.Request.Tenant, strconv.FormatUint(chain, 10)
	from := strings.ToLower(a.From)
	asset := "native"
	if er.Intent.Asset != nil {
		asset = strings.ToLower(er.Intent.Asset.Address)
	}
	return map[Scope]string{
		ScopeTenant:      k("tenant", t),
		ScopeAgent:       k("agent", t, er.Request.Actor.AgentID),
		ScopeWallet:      k("wallet", t, c, from),
		ScopeWalletAsset: k("wallet+asset", t, c, from, asset),
		ScopeDestination: k("destination", t, c, strings.ToLower(er.Intent.Destination)),
	}
}

func amountOf(er model.EnrichedRequest) (amount, error) {
	amt := amount{count: 1, units: new(big.Int)}
	// USD spend = value moved + the most the tx can pay in fees. Either one
	// unknown makes the request unpriced: a fee drain must not hide behind a
	// missing price.
	if er.AmountUSD != nil && (er.MaxFeeUSD != nil || er.Request.Action.Kind != model.KindEVMTx) {
		v, err := parseUSD(*er.AmountUSD, true)
		if err != nil {
			return amt, fmt.Errorf("limiter: amount_usd: %w", err)
		}
		if er.MaxFeeUSD != nil {
			f, err := parseUSD(*er.MaxFeeUSD, true)
			if err != nil {
				return amt, fmt.Errorf("limiter: max_fee_usd: %w", err)
			}
			v.Add(v, f)
		}
		amt.usd = v
	}
	if er.Intent.Amount != "" {
		v, ok := new(big.Int).SetString(er.Intent.Amount, 10)
		if !ok || v.Sign() < 0 {
			return amt, fmt.Errorf("limiter: intent amount %q is not a non-negative integer", er.Intent.Amount)
		}
		amt.units = v
	}
	return amt, nil
}

// Reserve implements engine.Limiter: all caps checked on all keys, then all
// keys updated, or nothing.
func (l *Limiter) Reserve(_ context.Context, id string, er model.EnrichedRequest, ttl time.Duration, ae *model.AuditEntry) error {
	if ttl <= 0 {
		return errors.New("limiter: ttl must be positive")
	}
	amt, err := amountOf(er)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.sweep(now)
	if e, ok := l.recs[id]; ok {
		if e.State == StateReserved && e.counted {
			return nil // idempotent: already holding capacity for this request
		}
		return fmt.Errorf("%w: %s (%s)", ErrDuplicateReservation, id, e.State)
	}
	ks := keys(er)
	for _, r := range l.rules {
		if r.UnknownDestinationsOnly && er.Destination.Known {
			continue
		}
		key := ks[r.Scope]
		used := l.used(key, r.window, now)
		if r.maxUSD != nil {
			if amt.usd == nil {
				return fmt.Errorf("%w (%s %s cap)", ErrUnpriced, r.Scope, r.Window)
			}
			if new(big.Int).Add(used.usd, amt.usd).Cmp(r.maxUSD) > 0 {
				return fmt.Errorf("%w: %s %s USD cap %s", engine.ErrCapExceeded, r.Scope, r.Window, microToDecimal(r.maxUSD))
			}
		}
		if r.MaxCount > 0 && used.count+amt.count > r.MaxCount {
			return fmt.Errorf("%w: %s %s count cap %d", engine.ErrCapExceeded, r.Scope, r.Window, r.MaxCount)
		}
		if r.maxUnits != nil && new(big.Int).Add(used.units, amt.units).Cmp(r.maxUnits) > 0 {
			return fmt.Errorf("%w: %s %s unit cap %s", engine.ErrCapExceeded, r.Scope, r.Window, r.maxUnits)
		}
	}
	keyList := make([]string, 0, len(scopes))
	for _, s := range scopes {
		keyList = append(keyList, ks[s])
	}
	rec := Record{
		ID: id, Keys: keyList, Count: amt.count, Units: amt.units.String(),
		Created: now, Expires: now.Add(ttl), State: StateReserved,
	}
	if amt.usd != nil {
		rec.USDMicro = amt.usd.String()
	}
	if err := l.persist(rec, ae); err != nil {
		return err
	}
	e := &entry{Record: rec, amt: amt}
	l.track(e)
	l.add(e)
	return nil
}

// Commit records that the action was broadcast. Committing after expiry
// still records the spend (loss bounding must count what happened) and
// returns ErrReservationExpired.
func (l *Limiter) Commit(_ context.Context, id, txRef string, ae *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.sweep(now)
	e, ok := l.recs[id]
	if !ok || e.State == StateReleased {
		return fmt.Errorf("%w: %s", ErrUnknownReservation, id)
	}
	if e.State == StateCommitted {
		if e.TxRef == txRef {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrAlreadyCommitted, id)
	}
	late := !e.counted
	rec := e.Record
	rec.State, rec.TxRef = StateCommitted, txRef
	t := now
	rec.CommittedAt = &t
	if err := l.persist(rec, ae); err != nil {
		return err
	}
	e.Record = rec
	if late {
		l.add(e)
		return fmt.Errorf("%w: %s committed after its reservation lapsed; spend recorded", ErrReservationExpired, id)
	}
	return nil
}

// Release frees a live reservation.
func (l *Limiter) Release(_ context.Context, id string, ae *model.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.sweep(now)
	e, ok := l.recs[id]
	switch {
	case !ok || e.State == StateReleased:
		return fmt.Errorf("%w: %s", ErrUnknownReservation, id)
	case e.State == StateCommitted:
		return fmt.Errorf("%w: %s", ErrAlreadyCommitted, id)
	case !e.counted:
		return fmt.Errorf("%w: %s", ErrReservationExpired, id)
	}
	rec := e.Record
	rec.State = StateReleased
	if err := l.persist(rec, ae); err != nil {
		return err
	}
	e.Record = rec
	l.subtract(e)
	return nil
}

// persist writes rec (and its audit entry, in the same transaction). With an
// entry, a failure means the state change AND its record are both absent:
// reported as engine.ErrAuditUnavailable, because the decision cannot be
// recorded.
func (l *Limiter) persist(rec Record, ae *model.AuditEntry) error {
	if err := l.store.Put(rec, ae); err != nil {
		if ae != nil {
			return fmt.Errorf("%w: limiter %s not recorded: %v", engine.ErrAuditUnavailable, rec.State, err)
		}
		return fmt.Errorf("limiter: persist %s: %w", rec.State, err)
	}
	return nil
}

// Enrich implements engine.Enricher: wallet-scope velocity (committed +
// reserved) for the policy context.
func (l *Limiter) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.sweep(now)
	key := keys(*er)[ScopeWallet]
	for i, name := range []string{"1m", "1h", "24h"} {
		u := l.used(key, i, now)
		er.Velocity[name] = model.Velocity{USD: microToDecimal(u.usd), Count: int(u.count)}
	}
	return nil
}

// Usage reports committed + reserved totals for one scope key of a request
// over a window: what caps are checked against. For tests and metrics.
func (l *Limiter) Usage(er model.EnrichedRequest, s Scope, window time.Duration) (usdMicro *big.Int, count int64, units *big.Int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.sweep(now)
	for i, w := range Windows {
		if w == window {
			u := l.used(keys(er)[s], i, now)
			return u.usd, u.count, u.units
		}
	}
	panic("limiter: unknown window " + window.String())
}

// ---- internals (l.mu held) ----

func granularity(i int) time.Duration { return Windows[i] / subBuckets }

// used sums every sub-bucket that overlaps (now - window, now].
func (l *Limiter) used(key string, w int, now time.Time) bucket {
	out := bucket{usd: new(big.Int), units: new(big.Int)}
	ku, ok := l.usage[key]
	if !ok {
		return out
	}
	g := int64(granularity(w))
	cutoff := now.Add(-Windows[w]).UnixNano()
	for idx, b := range ku.buckets[w] {
		if (idx+1)*g > cutoff {
			out.usd.Add(out.usd, b.usd)
			out.count += b.count
			out.units.Add(out.units, b.units)
		}
	}
	return out
}

func (l *Limiter) add(e *entry)      { l.apply(e, 1) }
func (l *Limiter) subtract(e *entry) { l.apply(e, -1) }

func (l *Limiter) apply(e *entry, sign int64) {
	if (sign > 0) == e.counted {
		return
	}
	if l.afterChange != nil {
		defer l.afterChange(l.clock())
	}
	e.counted = sign > 0
	usd := e.amt.usd
	if usd == nil {
		usd = new(big.Int) // unpriced: counts toward count/unit caps only
	}
	for _, key := range e.Keys {
		ku, ok := l.usage[key]
		if !ok {
			ku = &keyUsage{}
			for i := range ku.buckets {
				ku.buckets[i] = map[int64]*bucket{}
			}
			l.usage[key] = ku
		}
		for w := range Windows {
			idx := e.Created.UnixNano() / int64(granularity(w))
			b, ok := ku.buckets[w][idx]
			if !ok {
				b = &bucket{usd: new(big.Int), units: new(big.Int)}
				ku.buckets[w][idx] = b
			}
			if sign > 0 {
				b.usd.Add(b.usd, usd)
				b.units.Add(b.units, e.amt.units)
			} else {
				b.usd.Sub(b.usd, usd)
				b.units.Sub(b.units, e.amt.units)
			}
			b.count += sign * e.amt.count
			if b.count == 0 && b.usd.Sign() == 0 && b.units.Sign() == 0 {
				delete(ku.buckets[w], idx)
			}
		}
	}
}

// retention is how long records are kept: past the longest window plus one
// sub-bucket and the longest TTL, so duplicate IDs stay detectable for as
// long as they could matter.
var retention = Windows[len(Windows)-1] + granularity(len(Windows)-1) + model.MaxTTL

// track indexes a new record. Records arrive in creation order (the clock is
// monotonic per process; Load sorts), so byTime stays sorted.
func (l *Limiter) track(e *entry) {
	l.recs[e.ID] = e
	l.byTime = append(l.byTime, e)
	if e.State == StateReserved {
		heap.Push(&l.expiry, e)
	}
}

// sweep stops counting lapsed reservations and forgets records past
// retention. Expiry is a function of time, so it needs no write: on reload a
// lapsed reservation is simply not counted.
func (l *Limiter) sweep(now time.Time) {
	for len(l.expiry) > 0 && !now.Before(l.expiry[0].Expires) {
		e := heap.Pop(&l.expiry).(*entry)
		if e.State == StateReserved && e.counted {
			l.subtract(e)
		}
	}
	var forget []string
	n := 0
	for n < len(l.byTime) && now.Sub(l.byTime[n].Created) > retention {
		e := l.byTime[n]
		if e.counted {
			l.subtract(e) // committed spend older than every window
		}
		delete(l.recs, e.ID)
		forget = append(forget, e.ID)
		n++
	}
	if n == 0 {
		return
	}
	l.byTime = l.byTime[n:]
	_ = l.store.Delete(forget) // best effort: Load prunes past retention too
}

// expiryHeap orders reservations by expiry.
type expiryHeap []*entry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].Expires.Before(h[j].Expires) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(*entry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

func microToDecimal(v *big.Int) string {
	m := big.NewInt(1_000_000)
	ip, fp := new(big.Int).QuoRem(v, m, new(big.Int))
	s := ip.String()
	if frac := strings.TrimRight(fmt.Sprintf("%06s", fp.String()), "0"); frac != "" {
		s += "." + frac
	}
	return s
}
