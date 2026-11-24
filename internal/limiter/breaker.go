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
// Only a quorum (at least 2) of distinct approver OWNERS can close it (M of
// N, the same Ed25519 approver keys that approve escalations, CS-151;
// internal/approval). Each reset is an Ed25519-signed envelope
// (spec/approval-signature-v1.md §3), verified against the configured
// approver keys and the open trip before it counts toward Quorum
// (internal/approval.Tally dedupes by owner, not by key — two keys with the
// same owner count once). A vote is durable and audited before it counts,
// and expires at the signature's own expiry (bounded to at most 1h ahead).
// An owner with a live vote cannot vote again.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
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

// breakerVoteToApproval converts a stored, already-verified vote back into
// an approval.Vote, so ResetBreaker can replay the tenant's live votes
// through a fresh approval.Tally on every call (Tally itself persists
// nothing; the breaker's own store is the durable record, LLD §11).
func breakerVoteToApproval(v model.BreakerVote) approval.Vote {
	return approval.Vote{Kid: v.Approver, Owner: approval.Owner{AgentID: v.OwnerAgentID, KeyID: v.OwnerKeyID},
		Decision: approval.ResetDecision, Expiry: v.ExpiresAt}
}

// ResetBreaker verifies sig — an Ed25519-signed breaker-reset envelope
// (spec/approval-signature-v1.md §3) — against the configured approver keys
// and the tenant's open trip, and records its vote toward Quorum distinct
// OWNERS (CS-151: two keys configured with the same owner count once,
// internal/approval.Tally). A vote counts for the signature's own expiry
// (bounded to at most 1h ahead of when it is checked); votes that have
// expired are discarded with this one, and the discard is audited in the
// same transaction. It returns the status after the vote: still open
// (quorum not met) or closed.
//
// A signature that fails verification (unknown key, wrong tenant, bad
// signature, expired, too far ahead, wrong decision, or bound to a
// different trip) returns the *approval.VerifyError and changes nothing —
// it is not a vote and is not stored. An owner that already holds a live
// vote is refused (model.ErrDuplicateVote), and a closed breaker returns
// model.ErrBreakerNotOpen.
func (l *Limiter) ResetBreaker(_ context.Context, tenant string, sig approval.SignedBreakerReset) (model.BreakerStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.breakers[tenant]
	if b == nil {
		return l.status(tenant), model.ErrBreakerNotOpen
	}
	now := l.clock()
	if l.approvers == nil {
		return l.status(tenant), errors.New("limiter: no approver keys configured; breaker reset is disabled")
	}
	k, verr := approval.VerifyBreakerReset(l.approvers, sig, approval.BreakerResetWant{Tenant: tenant, TripRequestID: b.TripRequestID}, now)
	if verr != nil {
		return l.status(tenant), verr
	}

	live, expired := splitVotes(b.Votes, now)
	tally := approval.NewTally(l.quorum, "", "") // no requester to exclude for a breaker reset (spec §8)
	for _, bv := range live {
		_, _ = tally.Add(breakerVoteToApproval(bv), now)
	}
	if _, err := tally.Add(approval.VoteFromBreakerReset(k, sig), now); err != nil {
		if errors.Is(err, approval.ErrDuplicateVote) {
			return l.status(tenant), model.ErrDuplicateVote
		}
		return l.status(tenant), err
	}

	var entries []*model.AuditEntry
	if len(expired) > 0 {
		entries = append(entries, &model.AuditEntry{Type: model.AuditBreaker, Body: map[string]any{
			"event": BreakerVoteExpired, "tenant": tenant, "trip_request_id": b.TripRequestID,
			"expired": expired, "vote_ttl": model.BreakerVoteTTL.String()}})
	}
	next := *b
	next.Votes = append(live, model.BreakerVote{Approver: k.ID, OwnerAgentID: k.Owner.AgentID, OwnerKeyID: k.Owner.KeyID,
		At: now, ExpiresAt: time.Unix(sig.Expiry, 0)})
	approvers := approverIDs(next.Votes)
	body := map[string]any{"event": BreakerResetVote, "tenant": tenant, "trip_request_id": b.TripRequestID,
		"approver": k.ID, "kid": k.Kid, "owner": k.Owner, "approvers": approvers, "votes": len(next.Votes), "quorum": l.quorum}
	closing := tally.Resolution().Outcome == approval.Approved
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
