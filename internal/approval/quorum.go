package approval

import (
	"errors"
	"fmt"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// MinQuorumProduction is the fewest distinct approver keys a quorum may
// require once stopbard is not running -dev-world (spec §9). It is the
// same floor as model.MinBreakerQuorum, which CS-124's breaker already
// enforces; CS-151 applies it to escalation approvals too.
const MinQuorumProduction = model.MinBreakerQuorum

// ErrDuplicateVote means this key already holds a live vote (spec §9): it
// is refused, not counted a second time.
var ErrDuplicateVote = errors.New("approval: this key already holds a live vote")

// ErrAlreadyResolved means the tally already reached a final resolution
// (quorum met, or a reject); every vote after that is refused rather than
// re-opening or re-counting it (spec §9).
var ErrAlreadyResolved = errors.New("approval: already resolved")

// Outcome is the result of a Tally.
type Outcome int

const (
	// Pending: not enough live, distinct approve votes yet, and no reject.
	Pending Outcome = iota
	// Approved: quorum of distinct approve votes reached.
	Approved
	// Rejected: at least one valid reject vote (escalations only).
	Rejected
)

// Resolution is what a Tally currently holds.
type Resolution struct {
	Outcome Outcome
	// Approvers lists the distinct kids counted toward Approved, or the
	// single kid that caused Rejected. Empty while Pending.
	Approvers []string
}

// Vote is one verified signature to count (the caller has already run
// VerifyEscalation or VerifyBreakerReset; Tally trusts it).
type Vote struct {
	Kid      string
	Decision string // Approve, Reject or ResetDecision
	Expiry   time.Time
}

// Tally accumulates verified votes toward an M-of-N quorum and resolves
// exactly once (spec §9). It is pure: it persists nothing, so whatever
// stores pending escalations or breaker trips can wrap it over its own
// durable vote list without this package knowing how.
type Tally struct {
	required   int
	votes      map[string]Vote
	resolution Resolution
}

// NewTally starts a tally that resolves Approved once required distinct
// keys hold a live approve vote (or ResetDecision vote, for a breaker
// reset, where required votes of the one decision are all that exist).
func NewTally(required int) *Tally {
	return &Tally{required: required, votes: map[string]Vote{}}
}

// Add records v at time now and returns the resulting resolution. Once a
// Tally has resolved, every later Add returns the same resolution and
// ErrAlreadyResolved: it never re-opens or re-counts. A second live vote
// from a kid that already holds one returns ErrDuplicateVote and does not
// change the tally. Expired votes already held are discarded before v is
// counted, so a kid whose earlier vote expired may vote again.
func (t *Tally) Add(v Vote, now time.Time) (Resolution, error) {
	if t.resolution.Outcome != Pending {
		return t.resolution, ErrAlreadyResolved
	}
	for kid, existing := range t.votes {
		if !now.Before(existing.Expiry) {
			delete(t.votes, kid)
		}
	}
	if v.Decision == Reject {
		t.resolution = Resolution{Outcome: Rejected, Approvers: []string{v.Kid}}
		return t.resolution, nil
	}
	if _, live := t.votes[v.Kid]; live {
		return t.resolution, ErrDuplicateVote
	}
	t.votes[v.Kid] = v
	if len(t.votes) >= t.required {
		approvers := make([]string, 0, len(t.votes))
		for kid := range t.votes {
			approvers = append(approvers, kid)
		}
		t.resolution = Resolution{Outcome: Approved, Approvers: approvers}
	}
	return t.resolution, nil
}

// Resolution reports the tally's current state without adding a vote.
func (t *Tally) Resolution() Resolution { return t.resolution }

// Live reports the distinct, unexpired votes currently held, for display
// (e.g. breaker status) while Pending.
func (t *Tally) Live(now time.Time) []Vote {
	out := make([]Vote, 0, len(t.votes))
	for _, v := range t.votes {
		if now.Before(v.Expiry) {
			out = append(out, v)
		}
	}
	return out
}

// ValidateQuorum enforces spec §9's floor: a production deployment
// (devWorld false) must configure a quorum of at least MinQuorumProduction
// distinct approver keys. stopbard calls this before it starts.
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
