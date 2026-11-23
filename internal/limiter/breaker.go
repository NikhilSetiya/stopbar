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
// Only a quorum of distinct approver identities can close it (M of N, the same
// approver keys that approve escalations, CS-151). Each vote is durable and
// audited before it counts, votes are bound to the trip they were cast on, and
// one identity voting twice counts once.

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
	BreakerReset     = "reset"
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
	if b := l.breakers[tenant]; b != nil {
		out := *b
		out.Votes = slices.Clone(b.Votes)
		return out
	}
	return model.BreakerStatus{Tenant: tenant, Votes: []model.BreakerVote{}, Quorum: l.quorum}
}

// ResetBreaker records approver's vote to reset the tenant's open breaker and
// closes it once Quorum distinct approvers have voted. It returns the status
// after the vote: still open (vote recorded, quorum not met) or closed. A
// repeat vote by the same approver changes nothing. A closed breaker returns
// model.ErrBreakerNotOpen.
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
	if slices.ContainsFunc(b.Votes, func(v model.BreakerVote) bool { return v.Approver == approver }) {
		return l.status(tenant), nil
	}
	next := *b
	next.Votes = append(slices.Clone(b.Votes), model.BreakerVote{Approver: approver, At: l.clock()})
	approvers := make([]string, len(next.Votes))
	for i, v := range next.Votes {
		approvers[i] = v.Approver
	}
	body := map[string]any{"event": BreakerResetVote, "tenant": tenant, "trip_request_id": b.TripRequestID,
		"approver": approver, "approvers": approvers, "votes": len(next.Votes), "quorum": l.quorum}
	closing := len(next.Votes) >= l.quorum
	stored := next
	if closing {
		body["event"] = BreakerReset
		stored = model.BreakerStatus{Tenant: tenant, Votes: []model.BreakerVote{}, Quorum: l.quorum}
	}
	// Durable before visible: closing loosens, so it must never happen unrecorded.
	if err := l.store.PutBreaker(stored, &model.AuditEntry{Type: model.AuditBreaker, Body: body}); err != nil {
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
