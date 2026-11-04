package limiter

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

var (
	_  engine.Limiter  = (*Limiter)(nil)
	_  engine.Enricher = (*Limiter)(nil)
	bg                 = context.Background()
)

// fakeClock is safe for concurrent use; tests never sleep.
type fakeClock struct{ ns atomic.Int64 }

func newClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC).UnixNano()) // aligned to every sub-bucket
	return c
}
func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

func newLimiter(t testing.TB, c *fakeClock, rules ...Rule) *Limiter {
	t.Helper()
	l, err := New(Config{Rules: rules, Clock: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// req builds an enriched request. usd "" means unpriced.
func req(wallet, dest, usd, units string, known bool) model.EnrichedRequest {
	chain := uint64(8453)
	er := model.EnrichedRequest{
		Request: model.ActionRequest{Tenant: "acme", Actor: model.Actor{AgentID: "agent-" + wallet},
			Action: model.Action{Kind: model.KindEVMTx, ChainID: &chain, From: wallet}},
		Intent:      model.IntentSummary{Kind: "transfer", Amount: units, Destination: dest, Asset: &model.Asset{Address: "0xtoken"}},
		Destination: model.DestinationInfo{Known: known},
		Velocity:    map[string]model.Velocity{},
	}
	if usd != "" {
		zero := "0"
		er.AmountUSD, er.MaxFeeUSD = &usd, &zero
	}
	return er
}

// Value + max fee is what a request can spend; both count against USD caps.
func TestMaxFeeCountsTowardUSDCaps(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	er := req(walletA, dest, "10", "1", true)
	fee := "90"
	er.MaxFeeUSD = &fee
	mustReserve(t, l, "r1", er) // 10 + 90 = 100: exactly at the cap
	if got := usd(t, l, er, ScopeWallet); got != "100" {
		t.Fatalf("usage %s, want value+fee 100", got)
	}
	drain := req(walletA, dest, "0", "0", true) // zero value...
	big := "0.000001"
	drain.MaxFeeUSD = &big // ...but any fee at all is over the cap
	wantErr(t, l.Reserve(bg, "r2", drain, time.Minute, nil), engine.ErrCapExceeded)

	unpricedFee := req(walletA, dest, "1", "1", true)
	unpricedFee.MaxFeeUSD = nil // value known, fee price unknown
	wantErr(t, l.Reserve(bg, "r3", unpricedFee, time.Minute, nil), ErrUnpriced)
}

func usd(t testing.TB, l *Limiter, er model.EnrichedRequest, s Scope) string {
	t.Helper()
	v, _, _ := l.Usage(er, s, time.Hour)
	return microToDecimal(v)
}

func mustReserve(t testing.TB, l *Limiter, id string, er model.EnrichedRequest) {
	t.Helper()
	if err := l.Reserve(bg, id, er, time.Minute, nil); err != nil {
		t.Fatalf("reserve %s: %v", id, err)
	}
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("err = %v, want %v", err, target)
	}
}

const walletA, walletB, dest = "0xaaaa", "0xbbbb", "0xdddd"

// At the cap is allowed; one micro-dollar over is rejected; releasing makes
// exactly that capacity available again.
func TestCapBoundaryExact(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	mustReserve(t, l, "r1", req(walletA, dest, "60", "1", true))
	mustReserve(t, l, "r2", req(walletA, dest, "40", "1", true))
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "100" {
		t.Fatalf("usage %s", got)
	}
	wantErr(t, l.Reserve(bg, "r3", req(walletA, dest, "0.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	if err := l.Release(bg, "r2", nil); err != nil {
		t.Fatal(err)
	}
	wantErr(t, l.Reserve(bg, "r4", req(walletA, dest, "40.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	mustReserve(t, l, "r5", req(walletA, dest, "40", "1", true))
}

// One key over its cap means nothing is reserved on any key.
func TestAllOrNothingAcrossKeys(t *testing.T) {
	l := newLimiter(t, newClock(),
		Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"},
		Rule{Scope: ScopeTenant, Window: "1h", MaxUSD: "150"})
	mustReserve(t, l, "a1", req(walletA, dest, "90", "1", true))
	mustReserve(t, l, "b1", req(walletB, dest, "50", "1", true))

	// Wallet A would exceed its own cap; tenant has room. Nothing may move.
	wantErr(t, l.Reserve(bg, "a2", req(walletA, dest, "20", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	// Wallet B has room; tenant would exceed. Wallet B must not move.
	wantErr(t, l.Reserve(bg, "b2", req(walletB, dest, "20", "1", true), time.Minute, nil), engine.ErrCapExceeded)

	a, b := req(walletA, dest, "", "", true), req(walletB, dest, "", "", true)
	for _, c := range []struct {
		er    model.EnrichedRequest
		scope Scope
		want  string
	}{{a, ScopeWallet, "90"}, {b, ScopeWallet, "50"}, {a, ScopeTenant, "140"}, {a, ScopeAgent, "90"}, {b, ScopeDestination, "140"}} {
		if got := usd(t, l, c.er, c.scope); got != c.want {
			t.Errorf("%s usage %s, want %s (a rejected reserve leaked)", c.scope, got, c.want)
		}
	}
}

func TestReserveIsIdempotentByRequestID(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	er := req(walletA, dest, "70", "1", true)
	mustReserve(t, l, "r1", er)
	mustReserve(t, l, "r1", er) // retry of the same request
	if got := usd(t, l, er, ScopeWallet); got != "70" {
		t.Fatalf("double counted: %s", got)
	}
	if err := l.Release(bg, "r1", nil); err != nil {
		t.Fatal(err)
	}
	wantErr(t, l.Reserve(bg, "r1", er, time.Minute, nil), ErrDuplicateReservation)
}

func TestTypedErrorsOnCommitAndRelease(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	wantErr(t, l.Commit(bg, "nope", "0x1", nil), ErrUnknownReservation)
	wantErr(t, l.Release(bg, "nope", nil), ErrUnknownReservation)

	mustReserve(t, l, "r1", req(walletA, dest, "10", "1", true))
	if err := l.Release(bg, "r1", nil); err != nil {
		t.Fatal(err)
	}
	wantErr(t, l.Release(bg, "r1", nil), ErrUnknownReservation)
	wantErr(t, l.Commit(bg, "r1", "0x1", nil), ErrUnknownReservation)

	mustReserve(t, l, "r2", req(walletA, dest, "10", "1", true))
	if err := l.Commit(bg, "r2", "0xabc", nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Commit(bg, "r2", "0xabc", nil); err != nil {
		t.Fatalf("repeat commit with the same tx: %v", err)
	}
	wantErr(t, l.Commit(bg, "r2", "0xother", nil), ErrAlreadyCommitted)
	wantErr(t, l.Release(bg, "r2", nil), ErrAlreadyCommitted)
}

// A reservation counts until exactly its expiry, then frees its capacity.
func TestExpiryReleasesAtTheEdge(t *testing.T) {
	c := newClock()
	l := newLimiter(t, c, Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	mustReserve(t, l, "r1", req(walletA, dest, "100", "1", true)) // ttl 1m
	c.Advance(time.Minute - time.Nanosecond)
	wantErr(t, l.Reserve(bg, "r2", req(walletA, dest, "0.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	c.Advance(time.Nanosecond)
	mustReserve(t, l, "r3", req(walletA, dest, "100", "1", true))
	wantErr(t, l.Release(bg, "r1", nil), ErrReservationExpired)
}

// A late commit still records the spend: loss bounding counts what happened.
func TestLateCommitRecordsSpend(t *testing.T) {
	c := newClock()
	l := newLimiter(t, c, Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	mustReserve(t, l, "r1", req(walletA, dest, "80", "1", true))
	c.Advance(2 * time.Minute)
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "0" {
		t.Fatalf("lapsed reservation still counted: %s", got)
	}
	wantErr(t, l.Commit(bg, "r1", "0xlate", nil), ErrReservationExpired)
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "80" {
		t.Fatalf("late commit not counted: %s", got)
	}
}

// Committed spend leaves a window no earlier than window + one sub-bucket.
func TestWindowRollover(t *testing.T) {
	c := newClock()
	l := newLimiter(t, c, Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"}, Rule{Scope: ScopeWallet, Window: "24h", MaxUSD: "250"})
	mustReserve(t, l, "r1", req(walletA, dest, "100", "1", true))
	if err := l.Commit(bg, "r1", "0x1", nil); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Hour + time.Minute - time.Nanosecond)
	wantErr(t, l.Reserve(bg, "r2", req(walletA, dest, "0.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	c.Advance(time.Nanosecond)
	mustReserve(t, l, "r3", req(walletA, dest, "100", "1", true))
	if err := l.Commit(bg, "r3", "0x3", nil); err != nil {
		t.Fatal(err)
	}
	// Both spends are still inside 24h: counted once each, no double count.
	v, n, _ := l.Usage(req(walletA, dest, "", "", true), ScopeWallet, 24*time.Hour)
	if microToDecimal(v) != "200" || n != 2 {
		t.Fatalf("24h usage %s / %d", microToDecimal(v), n)
	}
	wantErr(t, l.Reserve(bg, "r4", req(walletA, dest, "50.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	c.Advance(24*time.Hour + 24*time.Minute)
	if v, n, _ := l.Usage(req(walletA, dest, "", "", true), ScopeWallet, 24*time.Hour); v.Sign() != 0 || n != 0 {
		t.Fatalf("spend not dropped after 24h: %s / %d", v, n)
	}
}

// With no price, USD caps fail closed and unit/count caps still bound loss.
func TestUnpricedRequests(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	wantErr(t, l.Reserve(bg, "r1", req(walletA, dest, "", "5", true), time.Minute, nil), ErrUnpriced)

	l = newLimiter(t, newClock(),
		Rule{Scope: ScopeWalletAsset, Window: "1h", MaxUnits: "1000"},
		Rule{Scope: ScopeWallet, Window: "1h", MaxCount: 3})
	mustReserve(t, l, "r1", req(walletA, dest, "", "600", true))
	wantErr(t, l.Reserve(bg, "r2", req(walletA, dest, "", "401", true), time.Minute, nil), engine.ErrCapExceeded)
	mustReserve(t, l, "r3", req(walletA, dest, "", "400", true))
	mustReserve(t, l, "r4", req(walletA, dest, "", "0", true))
	wantErr(t, l.Reserve(bg, "r5", req(walletA, dest, "", "0", true), time.Minute, nil), engine.ErrCapExceeded) // 4th tx
}

func TestUnknownDestinationCountCap(t *testing.T) {
	l := newLimiter(t, newClock(), Rule{Scope: ScopeDestination, Window: "24h", MaxCount: 2, UnknownDestinationsOnly: true})
	mustReserve(t, l, "u1", req(walletA, dest, "1", "1", false))
	mustReserve(t, l, "u2", req(walletA, dest, "1", "1", false))
	wantErr(t, l.Reserve(bg, "u3", req(walletA, dest, "1", "1", false), time.Minute, nil), engine.ErrCapExceeded)
	for i := range 5 {
		mustReserve(t, l, fmt.Sprintf("k%d", i), req(walletA, "0xknown", "1", "1", true))
	}
}

func TestKeysDoNotCollide(t *testing.T) {
	a, b := req(walletA, dest, "", "", true), req(walletA, dest, "", "", true)
	a.Request.Tenant, a.Request.Actor.AgentID = "t|x", "y"
	b.Request.Tenant, b.Request.Actor.AgentID = "t", "x|y"
	if keys(a)[ScopeAgent] == keys(b)[ScopeAgent] {
		t.Fatalf("agent keys collide: %s", keys(a)[ScopeAgent])
	}
}

func TestEnrichSetsVelocity(t *testing.T) {
	l := newLimiter(t, newClock())
	mustReserve(t, l, "r1", req(walletA, dest, "12.5", "1", true))
	er := req(walletA, dest, "1", "1", true)
	if err := l.Enrich(bg, &er); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"1m", "1h", "24h"} {
		if v := er.Velocity[w]; v.USD != "12.5" || v.Count != 1 {
			t.Errorf("%s velocity %+v", w, v)
		}
	}
}

func TestRuleValidation(t *testing.T) {
	for name, r := range map[string]Rule{
		"unknown scope":          {Scope: "planet", Window: "1h", MaxCount: 1},
		"odd window":             {Scope: ScopeWallet, Window: "2h", MaxCount: 1},
		"no cap":                 {Scope: ScopeWallet, Window: "1h"},
		"usd too precise":        {Scope: ScopeWallet, Window: "1h", MaxUSD: "1.0000001"},
		"usd not decimal":        {Scope: ScopeWallet, Window: "1h", MaxUSD: "1e3"},
		"units off wallet+asset": {Scope: ScopeWallet, Window: "1h", MaxUnits: "5"},
		"unknown-only off dest":  {Scope: ScopeWallet, Window: "1h", MaxCount: 1, UnknownDestinationsOnly: true},
		"negative count":         {Scope: ScopeWallet, Window: "1h", MaxCount: -1},
	} {
		if _, err := New(Config{Rules: []Rule{r}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseUSDRoundsAmountsUp(t *testing.T) {
	v, err := parseUSD("0.0000001", true)
	if err != nil || v.Int64() != 1 {
		t.Fatalf("got %v %v", v, err)
	}
	if _, err := parseUSD("-1", true); err == nil {
		t.Fatal("negative accepted")
	}
}

// ---- durability ----

type failingStore struct{ MemStore }

func (failingStore) Put(Record, *model.AuditEntry) error { return errors.New("disk full") }

func TestStoreFailureChangesNothing(t *testing.T) {
	l, err := New(Config{Rules: []Rule{{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"}}, Store: failingStore{}, Clock: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve(bg, "r1", req(walletA, dest, "10", "1", true), time.Minute, nil); err == nil || errors.Is(err, engine.ErrCapExceeded) {
		t.Fatalf("err = %v, want a persistence error", err)
	}
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "0" {
		t.Fatalf("state changed despite failed write: %s", got)
	}
}

func TestBoltRestartKeepsCaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	c := newClock()
	rules := []Rule{{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"}}
	open := func() (*Limiter, *store.DB, *audit.Log) {
		db, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		lg, err := audit.New(audit.Config{DB: db})
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewBoltStore(db, lg)
		if err != nil {
			t.Fatal(err)
		}
		l, err := New(Config{Rules: rules, Store: s, Clock: c.Now})
		if err != nil {
			t.Fatal(err)
		}
		return l, db, lg
	}
	l, db, _ := open()
	entry := &model.AuditEntry{Type: model.AuditDecision, Body: map[string]any{"request_id": "r1"}}
	if err := l.Reserve(bg, "r1", req(walletA, dest, "60", "1", true), time.Minute, entry); err != nil {
		t.Fatal(err)
	}
	if err := l.Commit(bg, "r1", "0x1", &model.AuditEntry{Type: model.AuditCommit, Body: map[string]any{"request_id": "r1"}}); err != nil {
		t.Fatal(err)
	}
	mustReserve(t, l, "r2", req(walletA, dest, "30", "1", true)) // live
	_ = db.Close()

	l, db, _ = open() // "crash" and restart
	defer func() { _ = db.Close() }()
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "90" {
		t.Fatalf("restart reset usage: %s", got)
	}
	wantErr(t, l.Reserve(bg, "r3", req(walletA, dest, "10.000001", "1", true), time.Minute, nil), engine.ErrCapExceeded)
	wantErr(t, l.Reserve(bg, "r1", req(walletA, dest, "1", "1", true), time.Minute, nil), ErrDuplicateReservation)
	c.Advance(time.Minute) // r2 lapses
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "60" {
		t.Fatalf("after r2 lapsed: %s", got)
	}
	recs, err := audit.Records(db, 1, 0)
	if err != nil || len(recs) != 2 || recs[0].Type != model.AuditDecision || recs[1].Type != model.AuditCommit {
		t.Fatalf("audit records %+v %v", recs, err)
	}
}

// The reservation and its audit record are one transaction: if the record
// cannot be written, the reservation does not exist either.
func TestReserveAndAuditAreAtomic(t *testing.T) {
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err := NewBoltStore(db, nil) // no audit log: every audited write must fail
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(Config{Rules: []Rule{{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"}}, Store: s, Clock: newClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	err = l.Reserve(bg, "r1", req(walletA, dest, "10", "1", true), time.Minute, &model.AuditEntry{Type: model.AuditDecision, Body: 1})
	wantErr(t, err, engine.ErrAuditUnavailable)
	if got := usd(t, l, req(walletA, dest, "", "", true), ScopeWallet); got != "0" {
		t.Fatalf("unaudited reservation exists: %s", got)
	}
	if MemStore.Put(MemStore{}, Record{}, &model.AuditEntry{}) == nil {
		t.Fatal("MemStore silently dropped an audit entry")
	}
}

// ---- property test (the CS-122 acceptance bar) ----

// TestConcurrentReservationsNeverExceedCaps: 1,000 goroutines (20 ops each) reserve random
// amounts on two wallets sharing a tenant cap, then commit, release or let
// the reservation lapse while the clock moves. Every cap is checked inside
// the lock after every state change (so in every state the limiter passes
// through), and by eight observers while the run is in progress, not only at the end. Finally, usage must
// equal an independent ledger exactly: nothing double-counted or dropped.
func TestConcurrentReservationsNeverExceedCaps(t *testing.T) {
	const workers = 1000
	c := newClock()
	walletCap, tenantCap, countCap := big.NewInt(1_000_000_000), big.NewInt(1_500_000_000), int64(400) // $1,000 / $1,500
	l := newLimiter(t, c,
		Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "1000", MaxCount: countCap},
		Rule{Scope: ScopeTenant, Window: "1h", MaxUSD: "1500"},
		Rule{Scope: ScopeWalletAsset, Window: "1h", MaxUnits: "100000"})
	probeA, probeB := req(walletA, dest, "", "", true), req(walletB, dest, "", "", true)

	type outcome struct {
		wallet string
		usd    *big.Int
		state  string
	}
	var (
		mu     sync.Mutex
		ledger = map[string]*outcome{}
	)
	// Every state: the hook runs under the lock after each change to usage.
	var transitions, inLockViolations atomic.Int64
	l.afterChange = func(now time.Time) {
		transitions.Add(1)
		for _, key := range []string{keys(probeA)[ScopeWallet], keys(probeB)[ScopeWallet]} {
			if u := l.used(key, 1, now); u.usd.Cmp(walletCap) > 0 || u.count > countCap {
				inLockViolations.Add(1)
			}
		}
		if u := l.used(keys(probeA)[ScopeTenant], 1, now); u.usd.Cmp(tenantCap) > 0 {
			inLockViolations.Add(1)
		}
	}

	// Independent observers outside the lock, for a second opinion.
	stop := make(chan struct{})
	var samples, violations atomic.Int64
	var sampler sync.WaitGroup
	for range 8 {
		sampler.Add(1)
		go func() {
			defer sampler.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ua, na, unitsA := l.Usage(probeA, ScopeWallet, time.Hour)
				ub, _, _ := l.Usage(probeB, ScopeWallet, time.Hour)
				ut, _, _ := l.Usage(probeA, ScopeTenant, time.Hour)
				if ua.Cmp(walletCap) > 0 || ub.Cmp(walletCap) > 0 || ut.Cmp(tenantCap) > 0 || na > countCap || unitsA.Cmp(big.NewInt(100000)) > 0 {
					violations.Add(1)
				}
				samples.Add(1)
			}
		}()
	}
	const opsPerWorker = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(i), 7))
			<-start // all 1,000 contend from the same instant
			for op := range opsPerWorker {
				c.Advance(10 * time.Millisecond) // 20,000 ops ≈ 200s: TTLs lapse mid-run, the 1h window never rolls
				wallet := walletA
				if rng.IntN(2) == 0 {
					wallet = walletB
				}
				cents := 100 + rng.IntN(4000) // $1.00 .. $40.99
				amt := fmt.Sprintf("%d.%02d", cents/100, cents%100)
				id := fmt.Sprintf("req-%d-%d", i, op)
				ttl := time.Duration(30+rng.IntN(90)) * time.Second
				if err := l.Reserve(bg, id, req(wallet, dest, amt, fmt.Sprint(rng.IntN(400)), true), ttl, nil); err != nil {
					if !errors.Is(err, engine.ErrCapExceeded) {
						t.Errorf("reserve: %v", err)
					}
					continue
				}
				o := &outcome{wallet: wallet, usd: mustUSD(amt), state: StateReserved}
				switch p := rng.IntN(20); {
				case p < 2: // 10% commit; the rest release or lapse, so capacity recycles
					err := l.Commit(bg, id, "0x"+id, nil)
					switch {
					case err == nil, errors.Is(err, ErrReservationExpired): // late commit still records spend
						o.state = StateCommitted
					default:
						t.Errorf("commit: %v", err)
					}
				case p < 11:
					err := l.Release(bg, id, nil)
					switch {
					case err == nil:
						o.state = StateReleased
					case errors.Is(err, ErrReservationExpired):
					default:
						t.Errorf("release: %v", err)
					}
				}
				mu.Lock()
				ledger[id] = o
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stop)
	sampler.Wait()

	l.afterChange = nil
	if inLockViolations.Load() > 0 {
		t.Fatalf("a cap was exceeded in %d of %d states", inLockViolations.Load(), transitions.Load())
	}
	if violations.Load() > 0 {
		t.Fatalf("%d of %d external samples saw a cap exceeded mid-run", violations.Load(), samples.Load())
	}
	if transitions.Load() < 1000 || samples.Load() == 0 {
		t.Fatalf("only %d state changes and %d samples observed", transitions.Load(), samples.Load())
	}
	if len(ledger) == 0 || len(ledger) == workers*opsPerWorker {
		t.Fatalf("%d of %d reservations succeeded: caps never bit, or never allowed", len(ledger), workers*opsPerWorker)
	}

	// Exact reconciliation: once every reservation has lapsed (TTL ≤ 2m),
	// usage must equal the committed spend in the ledger, still inside the
	// 1h window (≈200s + 10m have passed).
	c.Advance(10 * time.Minute)
	want := map[string]*big.Int{walletA: new(big.Int), walletB: new(big.Int)}
	for _, o := range ledger {
		if o.state == StateCommitted {
			want[o.wallet].Add(want[o.wallet], o.usd)
		}
	}
	for w, probe := range map[string]model.EnrichedRequest{walletA: probeA, walletB: probeB} {
		got, _, _ := l.Usage(probe, ScopeWallet, time.Hour)
		if got.Cmp(want[w]) != 0 {
			t.Errorf("wallet %s: usage %s, ledger %s (double count or drop)", w, microToDecimal(got), microToDecimal(want[w]))
		}
	}
	t.Logf("%d of %d reservations allowed across %d goroutines; invariant held in all %d states; %d external samples; clock +%s",
		len(ledger), workers*opsPerWorker, workers, transitions.Load(), samples.Load(), c.Now().Sub(newClock().Now()))
}

func mustUSD(s string) *big.Int {
	v, err := parseUSD(s, true)
	if err != nil {
		panic(err)
	}
	return v
}
