package limiter

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

var _ engine.Breaker = (*Limiter)(nil)

var breakerRules = []Rule{
	{Scope: ScopeTenant, Window: "1h", MaxUSD: "100", CircuitBreaker: true},
	{Scope: ScopeWallet, Window: "1h", MaxUSD: "1000"},
}

// openBolt opens (or reopens) a limiter on a state file at path.
func openBolt(t *testing.T, path string, c *fakeClock, quorum int) (*Limiter, *store.DB) {
	t.Helper()
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
	l, err := New(Config{Rules: breakerRules, Store: s, Clock: c.Now, BreakerQuorum: quorum})
	if err != nil {
		t.Fatal(err)
	}
	return l, db
}

func open(t *testing.T, l *Limiter, tenant string) bool {
	t.Helper()
	o, err := l.CircuitOpen(bg, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// CS-124 acceptance at the limiter: a breach trips the breaker, which then
// refuses every request for that tenant (and no other) until a quorum of
// distinct approvers resets it, across a restart; every change is audited.
func TestCircuitBreakerTripAndQuorumReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	c := newClock()
	l, db := openBolt(t, path, c, 2)

	mustReserve(t, l, "r1", req(walletA, dest, "60", "1", true))
	// 60 + 41 > 100: the request trips the breaker, not a plain cap.
	wantErr(t, l.Reserve(bg, "r2", req(walletA, dest, "41", "1", true), time.Minute, nil), engine.ErrCircuitOpen)
	if !open(t, l, "acme") || open(t, l, "other") {
		t.Fatal("breaker should be open for acme only")
	}
	// Every request for the tenant is refused, even a tiny one on another wallet.
	wantErr(t, l.Reserve(bg, "r3", req(walletB, dest, "0.01", "1", true), time.Minute, nil), engine.ErrCircuitOpen)
	other := req(walletA, dest, "1", "1", true)
	other.Request.Tenant = "other"
	mustReserve(t, l, "r4", other)
	// It stays open after the window rolls past the spend: only a reset closes it.
	c.Advance(2 * time.Hour)
	wantErr(t, l.Reserve(bg, "r5", req(walletA, dest, "1", "1", true), time.Minute, nil), engine.ErrCircuitOpen)
	if got := l.Counters()["stopbar_circuit_breaker_trips_total"]; got != 1 {
		t.Fatalf("trips_total = %d, want 1", got)
	}

	// Restart: the open breaker is durable.
	_ = db.Close()
	l, db = openBolt(t, path, c, 2)
	if !open(t, l, "acme") {
		t.Fatal("restart closed the breaker")
	}
	st := l.BreakerStatus("acme")
	if err := st.Validate(); err != nil || st.TripRequestID != "r2" || st.Quorum != 2 {
		t.Fatalf("status %+v %v", st, err)
	}

	// Insufficient signatures: one vote leaves it open; the same identity
	// voting again is refused and writes nothing.
	st, err := l.ResetBreaker(bg, "acme", "ak_alice")
	if err != nil || !st.Open || len(st.Votes) != 1 {
		t.Fatalf("one vote: %+v %v", st, err)
	}
	if st, err := l.ResetBreaker(bg, "acme", "ak_alice"); !errors.Is(err, model.ErrDuplicateVote) || len(st.Votes) != 1 {
		t.Fatalf("repeat vote: %+v %v", st, err)
	}
	wantErr(t, l.Reserve(bg, "r6", req(walletA, dest, "1", "1", true), time.Minute, nil), engine.ErrCircuitOpen)
	if _, err := l.ResetBreaker(bg, "acme", ""); err == nil {
		t.Fatal("an anonymous vote was accepted")
	}

	// Votes survive a restart too, and the second distinct approver closes it.
	_ = db.Close()
	l, db = openBolt(t, path, c, 2)
	defer func() { _ = db.Close() }()
	st, err = l.ResetBreaker(bg, "acme", "ak_bob")
	if err != nil || st.Open || len(st.Votes) != 0 {
		t.Fatalf("quorum vote: %+v %v", st, err)
	}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	mustReserve(t, l, "r7", req(walletA, dest, "1", "1", true))
	if _, err := l.ResetBreaker(bg, "acme", "ak_carol"); !errors.Is(err, model.ErrBreakerNotOpen) {
		t.Fatalf("reset of a closed breaker: %v", err)
	}

	// Audit: trip, two votes (the repeat wrote nothing), reset; each in the
	// same transaction as the change.
	recs, err := audit.Records(db, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for _, r := range recs {
		if r.Type == model.AuditBreaker {
			events = append(events, r.Body.(map[string]any)["event"].(string))
		}
	}
	if want := []string{BreakerTrip, BreakerResetVote, BreakerReset}; len(events) != 3 || events[0] != want[0] || events[1] != want[1] || events[2] != want[2] {
		t.Fatalf("breaker audit events %v, want %v", events, want)
	}
}

// Votes expire after model.BreakerVoteTTL: an expired vote no longer counts
// (and shows as expired in the status), so a vote, a wait of more than an hour
// and a second vote leave the breaker open. The next vote discards the expired
// one, audited in the same transaction. Two fresh distinct votes close it.
func TestBreakerVotesExpire(t *testing.T) {
	c := newClock()
	l, db := openBolt(t, filepath.Join(t.TempDir(), "state.db"), c, 2)
	defer func() { _ = db.Close() }()
	wantErr(t, l.Reserve(bg, "trip", req(walletA, dest, "101", "1", true), time.Minute, nil), engine.ErrCircuitOpen)

	if _, err := l.ResetBreaker(bg, "acme", "ak_alice"); err != nil {
		t.Fatal(err)
	}
	c.Advance(model.BreakerVoteTTL - time.Second)
	if st := l.BreakerStatus("acme"); len(st.Votes) != 1 || len(st.ExpiredVotes) != 0 {
		t.Fatalf("vote expired early: %+v", st)
	}
	c.Advance(2 * time.Second) // > 1h after alice voted
	st := l.BreakerStatus("acme")
	if len(st.Votes) != 0 || len(st.ExpiredVotes) != 1 || st.ExpiredVotes[0].Approver != "ak_alice" || st.Validate() != nil {
		t.Fatalf("expiry not visible in status: %+v %v", st, st.Validate())
	}
	st, err := l.ResetBreaker(bg, "acme", "ak_bob")
	if err != nil || !st.Open || len(st.Votes) != 1 || len(st.ExpiredVotes) != 0 {
		t.Fatalf("second vote after the first expired must leave it open: %+v %v", st, err)
	}
	wantErr(t, l.Reserve(bg, "r1", req(walletA, dest, "1", "1", true), time.Minute, nil), engine.ErrCircuitOpen)
	// Alice's vote expired, so she may vote afresh: two live distinct votes close it.
	st, err = l.ResetBreaker(bg, "acme", "ak_alice")
	if err != nil || st.Open {
		t.Fatalf("two fresh distinct votes: %+v %v", st, err)
	}
	mustReserve(t, l, "r2", req(walletA, dest, "1", "1", true))

	recs, err := audit.Records(db, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for _, r := range recs {
		if r.Type == model.AuditBreaker {
			events = append(events, r.Body.(map[string]any)["event"].(string))
		}
	}
	want := []string{BreakerTrip, BreakerResetVote, BreakerVoteExpired, BreakerResetVote, BreakerReset}
	if !slices.Equal(events, want) {
		t.Fatalf("breaker audit events %v, want %v", events, want)
	}
	// The discard and the vote that found it share one transaction: adjacent
	// records, the discard followed by bob's vote.
	for i, r := range recs {
		if r.Type == model.AuditBreaker && r.Body.(map[string]any)["event"] == BreakerVoteExpired {
			next := recs[i+1].Body.(map[string]any)
			if next["event"] != BreakerResetVote || next["approver"] != "ak_bob" {
				t.Fatalf("discard not written with bob's vote: %+v", next)
			}
		}
	}
}

// A trip that cannot be recorded still opens the breaker (failing closed) and
// reports the audit failure; a reset that cannot be recorded changes nothing.
func TestCircuitBreakerFailsClosedWithoutAudit(t *testing.T) {
	l := newLimiter(t, newClock(), breakerRules...) // MemStore: cannot audit
	err := l.Reserve(bg, "r1", req(walletA, dest, "101", "1", true), time.Minute, nil)
	wantErr(t, err, engine.ErrAuditUnavailable)
	if !open(t, l, "acme") {
		t.Fatal("unrecorded trip left the breaker closed")
	}
	if _, err := l.ResetBreaker(bg, "acme", "ak_alice"); !errors.Is(err, engine.ErrAuditUnavailable) {
		t.Fatalf("unrecorded reset vote: %v", err)
	}
	if st := l.BreakerStatus("acme"); !st.Open || len(st.Votes) != 0 {
		t.Fatalf("unrecorded vote changed state: %+v", st)
	}
}

func TestCircuitBreakerConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"breaker off tenant scope": {Rules: []Rule{{Scope: ScopeWallet, Window: "1h", MaxUSD: "1", CircuitBreaker: true}}},
		"breaker per tx":           {Rules: []Rule{{Scope: ScopeTenant, Window: WindowTx, MaxUSD: "1", CircuitBreaker: true}}},
		"negative quorum":          {BreakerQuorum: -1},
		"quorum of one":            {BreakerQuorum: 1},
		"breaker as soft cap":      {Rules: []Rule{{Scope: ScopeTenant, Window: "1h", MaxUSD: "1", CircuitBreaker: true, Escalate: true}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	l, err := New(Config{})
	if err != nil || l.BreakerStatus("t").Quorum != DefaultBreakerQuorum {
		t.Fatalf("default quorum: %v", err)
	}
}
