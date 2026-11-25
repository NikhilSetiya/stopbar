package approval

import (
	"errors"
	"fmt"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// MinQuorumProduction is the fewest distinct approver OWNERS a quorum may
// require once stopbard is not running -dev-world (spec §9). It is the
// same floor as model.MinBreakerQuorum, which CS-124's breaker already
// enforces; CS-151 applies it to escalation approvals too.
const MinQuorumProduction = model.MinBreakerQuorum

// ErrDuplicateVote means this vote's owner already holds a live vote (spec
// §9) — whether cast with this exact key or a different key configured
// with the same Owner. It is refused, not counted a second time.
var ErrDuplicateVote = errors.New("approval: this owner already holds a live vote")

// ErrAlreadyResolved means the tally already reached a final resolution
// (quorum met, or a reject); every vote after that is refused rather than
// re-opening or re-counting it (spec §9).
var ErrAlreadyResolved = errors.New("approval: already resolved")

// Outcome is the result of a Tally.
type Outcome int

const (
	// Pending: not enough live, distinct-owner approve votes yet, and no reject.
	Pending Outcome = iota
	// Approved: quorum of distinct-owner approve votes reached.
	Approved
	// Rejected: at least one valid reject vote (escalations only).
	Rejected
)

// Resolution is what a Tally currently holds.
type Resolution struct {
	Outcome Outcome
	// Approvers lists the kids counted toward Approved (one per distinct
	// owner), or the single kid that caused Rejected. Empty while Pending.
	Approvers []string
	// Veto is the exact vote that caused Rejected (nil otherwise): the
	// single reject a caller alerts on and audits (Alerts.Veto,
	// VetoAuditEntry), not just its kid.
	Veto *Vote
}

// Vote is one verified signature to count (the caller has already run
// VerifyEscalation or VerifyBreakerReset; Tally trusts it). Owner is the
// matched key's configured Owner (spec §5) — it is what Tally dedupes and
// excludes on, not Kid.
// Vote's JSON tags matter: it is embedded directly in audit record bodies
// (Resolution.Veto, VetoAuditEntry), so its wire shape is the audit log's,
// not merely internal bookkeeping — lowercase, matching every other wire
// type in the codebase.
type Vote struct {
	Kid      string    `json:"kid"`
	Owner    Owner     `json:"owner"`
	Decision string    `json:"decision"` // Approve, Reject or ResetDecision
	Expiry   time.Time `json:"expiry"`
	// Sig is the verified envelope's own signature (base64url), carried
	// through for audit records that want the raw signature alongside the
	// kid and owner, not just Tally's own bookkeeping.
	Sig string `json:"sig,omitempty"`
}

// VoteFromEscalation builds the Vote to add to a Tally from a key
// VerifyEscalation matched and the envelope it verified. Call only after
// VerifyEscalation returns no error.
func VoteFromEscalation(k Key, s SignedEscalation) Vote {
	return Vote{Kid: k.Kid, Owner: k.Owner, Decision: s.Decision, Expiry: time.Unix(s.Expiry, 0), Sig: s.Sig}
}

// VoteFromBreakerReset builds the Vote to add to a Tally from a key
// VerifyBreakerReset matched and the envelope it verified. Call only after
// VerifyBreakerReset returns no error.
func VoteFromBreakerReset(k Key, s SignedBreakerReset) Vote {
	return Vote{Kid: k.Kid, Owner: k.Owner, Decision: s.Decision, Expiry: time.Unix(s.Expiry, 0), Sig: s.Sig}
}

// VoteFromContact builds the Vote to add to a Tally from a key VerifyContact
// matched and the envelope it verified.
func VoteFromContact(k Key, s SignedContact) Vote {
	return Vote{Kid: k.Kid, Owner: k.Owner, Decision: s.Decision, Expiry: time.Unix(s.Expiry, 0), Sig: s.Sig}
}

// Tally accumulates verified votes toward an M-of-N quorum of distinct
// OWNERS — not distinct keys — and resolves exactly once (spec §9). Two
// configured keys with the same Owner count as one: a single person
// holding two approver keys cannot satisfy a 2-of-N quorum alone. It is
// pure: it persists nothing, so whatever stores pending escalations or
// breaker trips can wrap it over its own durable vote list without this
// package knowing how.
type Tally struct {
	required int
	// excludeKeyID/excludeAgentID are the escalation's requester identity
	// (spec §7): a vote whose Owner matches either, by the same
	// either-field rule VerifyEscalation already enforces, never counts,
	// as defence in depth if an unverified Vote ever reaches Add. Both are
	// "" for a breaker reset, which has no requester to exclude (spec §8).
	excludeKeyID, excludeAgentID string
	byOwner                      map[string]Vote // keyed by Owner's canonical identity
	resolution                   Resolution
}

// NewTally starts a tally that resolves Approved once required distinct
// owners hold a live approve vote (or ResetDecision vote, for a breaker
// reset, where required votes of the one decision are all that exist).
// excludeRequesterKeyID and excludeRequesterAgentID are the escalation's
// requester identity (pass "", "" for a breaker reset, or when the
// deployment has no authenticated requester to exclude).
func NewTally(required int, excludeRequesterKeyID, excludeRequesterAgentID string) *Tally {
	return &Tally{required: required, excludeKeyID: excludeRequesterKeyID, excludeAgentID: excludeRequesterAgentID, byOwner: map[string]Vote{}}
}

// Add records v at time now and returns the resulting resolution. Once a
// Tally has resolved, every later Add returns the same resolution and
// ErrAlreadyResolved: it never re-opens or re-counts. A second live vote
// whose Owner already holds one (whether the same key or a different key
// with the same Owner) returns ErrDuplicateVote and does not change the
// tally. A vote whose Owner is the excluded requester identity returns a
// SELF_APPROVAL *VerifyError and does not change the tally, even though
// VerifyEscalation should already have refused it upstream — this is
// defence in depth, not the primary check. Expired votes already held are
// discarded before v is counted, so an owner whose earlier vote expired
// may vote again.
func (t *Tally) Add(v Vote, now time.Time) (Resolution, error) {
	if t.resolution.Outcome != Pending {
		return t.resolution, ErrAlreadyResolved
	}
	for owner, existing := range t.byOwner {
		if !now.Before(existing.Expiry) {
			delete(t.byOwner, owner)
		}
	}
	if v.Decision == Reject {
		vetoed := v
		t.resolution = Resolution{Outcome: Rejected, Approvers: []string{v.Kid}, Veto: &vetoed}
		return t.resolution, nil
	}
	if selfApproval(v.Owner, EscalationWant{RequesterKeyID: t.excludeKeyID, RequesterAgentID: t.excludeAgentID}) {
		return t.resolution, verr(CodeSelfApproval)
	}
	owner := v.Owner.identity()
	if _, live := t.byOwner[owner]; live {
		return t.resolution, ErrDuplicateVote
	}
	t.byOwner[owner] = v
	if len(t.byOwner) >= t.required {
		approvers := make([]string, 0, len(t.byOwner))
		for _, counted := range t.byOwner {
			approvers = append(approvers, counted.Kid)
		}
		t.resolution = Resolution{Outcome: Approved, Approvers: approvers}
	}
	return t.resolution, nil
}

// Resolution reports the tally's current state without adding a vote.
func (t *Tally) Resolution() Resolution { return t.resolution }

// Live reports the distinct-owner, unexpired votes currently held, for
// display (e.g. breaker status) while Pending.
func (t *Tally) Live(now time.Time) []Vote {
	out := make([]Vote, 0, len(t.byOwner))
	for _, v := range t.byOwner {
		if now.Before(v.Expiry) {
			out = append(out, v)
		}
	}
	return out
}

// ValidateQuorum enforces spec §9's floor: a production deployment
// (devWorld false) must configure a quorum of at least MinQuorumProduction
// distinct approver owners. stopbard calls this before it starts.
func ValidateQuorum(required int, devWorld bool) error {
	if devWorld {
		if required < 1 {
			return fmt.Errorf("approval: quorum must be at least 1, got %d", required)
		}
		return nil
	}
	if required < MinQuorumProduction {
		return fmt.Errorf("approval: quorum must be at least %d outside -dev-world, got %d", MinQuorumProduction, required)
	}
	return nil
}
