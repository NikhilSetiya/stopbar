package limiter

// Tenant circuit breaker (CS-124, FR-LIM-3, LLD §7.3).
//
// A tenant-scope rule marked circuit_breaker is the tenant's outflow cap. A
// request that would exceed it trips the breaker: the trip and its audit
// record are written in one transaction, a high-severity alert is logged and
// stopbar_circuit_breaker_trips_total goes up. While it is open, Reserve and
// CircuitOpen refuse every request for the tenant (the engine denies
// CIRCUIT_OPEN before policy, so escalations and approvals stop too).
//
// Only a quorum (at least 2) of distinct approver identities can close it (M of
// N, the same approver keys that approve escalations, CS-151). Each vote is
// durable and audited before it counts, is bound to the trip it was cast on,
// and expires after model.BreakerVoteTTL (1h). An identity with a live vote
// cannot vote again.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Breaker events, in the body of AuditBreaker records.
const (
	BreakerTrip      = "trip"
	BreakerResetVote = "reset_vote"
	// BreakerVoteExpired discards votes older than model.BreakerVoteTTL, in
	// the same transaction as the vote that found them.
	BreakerVoteExpired = "vote_expired"
	BreakerReset       = "reset"
)

// trip opens the tenant's breaker (l.mu held). It opens in memory even if the
// write fails: refusing the tenant is the safe direction. The failed write is
// reported as ErrAuditUnavailable, because the trip went unrecorded.
func (l *Limiter) trip(requestID, tenant, reason string, now time.Time) error {
	at := now
	b := &model.BreakerStatus{Tenant: tenant, Open: true, TrippedAt: &at, TripRequestID: requestID,
		Reason: reason, Votes: []model.BreakerVote{}, Quorum: l.quorum}
	werr := l.store.PutBreaker(*b, &model.AuditEntry{Type: model.AuditBreaker,
		Body: map[string]any{"event": BreakerTrip, "tenant": tenant, "request_id": requestID, "breaker": *b}})
	l.breakers[tenant] = b
	l.trips++
	l.log.Error("CIRCUIT BREAKER TRIPPED: every request for the tenant is denied until a quorum of approvers resets it",
		"severity", "high", "alert", "circuit_breaker_open", "metric", "stopbar_circuit_breaker_trips_total",
		"tenant", tenant, "request_id", requestID, "reason", reason, "quorum", l.quorum, "recorded", werr == nil)
	if werr != nil {
		return fmt.Errorf("%w: circuit breaker trip not recorded (breaker is open in memory): %v", engine.ErrAuditUnavailable, werr)
	}
	return fmt.Errorf("%w: tenant %q: %s", engine.ErrCircuitOpen, tenant, reason)
}

// CircuitOpen implements engine.Breaker.
func (l *Limiter) CircuitOpen(_ context.Context, tenant string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.breakers[tenant] != nil, nil
}

// BreakerStatus reports the tenant's breaker.
func (l *Limiter) BreakerStatus(tenant string) model.BreakerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status(tenant)
}

func (l *Limiter) status(tenant string) model.BreakerStatus {
	b := l.breakers[tenant]
	if b == nil {
		return model.BreakerStatus{Tenant: tenant, Votes: []model.BreakerVote{}, Quorum: l.quorum}
	}
	out := *b
	out.Votes, out.ExpiredVotes = splitVotes(b.Votes, l.clock())
	out.Quorum = l.quorum
	return out
}

// splitVotes separates live votes from those past their expiry. The stored
// breaker keeps expired votes until the next vote discards them (audited);
// only live ones ever count.
func splitVotes(votes []model.BreakerVote, now time.Time) (live, expired []model.BreakerVote) {
	live = []model.BreakerVote{}
	for _, v := range votes {
		if now.Before(v.ExpiresAt) {
			live = append(live, v)
		} else {
			expired = append(expired, v)
		}
	}
	return live, expired
}

func approverIDs(votes []model.BreakerVote) []string {
	ids := make([]string, len(votes))
	for i, v := range votes {
		ids[i] = v.Approver
	}
	return ids
}

// ResetBreaker records approver's vote to reset the tenant's open breaker and
// closes it once Quorum distinct approvers hold live votes. A vote counts for
// model.BreakerVoteTTL (1h); votes that have expired are discarded with this
// one, and the discard is audited in the same transaction. It returns the
// status after the vote: still open (quorum not met) or closed. An approver
// who already holds a live vote is refused (model.ErrDuplicateVote), and a
// closed breaker returns model.ErrBreakerNotOpen.
func (l *Limiter) ResetBreaker(_ context.Context, tenant, approver string) (model.BreakerStatus, error) {
	if approver == "" {
		return model.BreakerStatus{}, errors.New("limiter: a breaker reset vote needs an authenticated approver identity")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.breakers[tenant]
	if b == nil {
		return l.status(tenant), model.ErrBreakerNotOpen
	}
	now := l.clock()
	live, expired := splitVotes(b.Votes, now)
	if slices.ContainsFunc(live, func(v model.BreakerVote) bool { return v.Approver == approver }) {
		return l.status(tenant), model.ErrDuplicateVote
	}
	var entries []*model.AuditEntry
	if len(expired) > 0 {
		entries = append(entries, &model.AuditEntry{Type: model.AuditBreaker, Body: map[string]any{
			"event": BreakerVoteExpired, "tenant": tenant, "trip_request_id": b.TripRequestID,
			"expired": expired, "vote_ttl": model.BreakerVoteTTL.String()}})
	}
	next := *b
	next.Votes = append(live, model.BreakerVote{Approver: approver, At: now, ExpiresAt: now.Add(model.BreakerVoteTTL)})
	approvers := approverIDs(next.Votes)
	body := map[string]any{"event": BreakerResetVote, "tenant": tenant, "trip_request_id": b.TripRequestID,
		"approver": approver, "approvers": approvers, "votes": len(next.Votes), "quorum": l.quorum}
	closing := len(next.Votes) >= l.quorum
	stored := next
	if closing {
		body["event"] = BreakerReset
		stored = model.BreakerStatus{Tenant: tenant, Votes: []model.BreakerVote{}, Quorum: l.quorum}
	}
	entries = append(entries, &model.AuditEntry{Type: model.AuditBreaker, Body: body})
	// Durable before visible: closing loosens, so it must never happen unrecorded.
	if err := l.store.PutBreaker(stored, entries...); err != nil {
		return l.status(tenant), fmt.Errorf("%w: breaker %s not recorded: %v", engine.ErrAuditUnavailable, body["event"], err)
	}
	if closing {
		delete(l.breakers, tenant)
		l.resets++
		l.log.Warn("circuit breaker reset", "tenant", tenant, "approvers", approvers, "quorum", l.quorum)
	} else {
		l.breakers[tenant] = &next
	}
	return l.status(tenant), nil
}

// Counters are the limiter's metrics, for /metrics. An increase in
// stopbar_circuit_breaker_trips_total is the alert: a tenant has been halted.
func (l *Limiter) Counters() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return map[string]uint64{
		"stopbar_circuit_breaker_trips_total":  l.trips,
		"stopbar_circuit_breaker_resets_total": l.resets,
	}
}
