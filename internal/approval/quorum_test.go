package approval

import (
	"testing"
	"time"
)

// vote builds a Vote whose Owner is 1:1 with kid (Owner{KeyID: kid}),
// matching the previous by-key tests' intent: unless a test explicitly
// gives two votes the same Owner, each kid here is its own distinct owner.
func vote(kid, decision string, expiry time.Time) Vote {
	return Vote{Kid: kid, Owner: Owner{KeyID: kid}, Decision: decision, Expiry: expiry}
}

func newTally(required int) *Tally { return NewTally(required, "", "") }

func TestTallyBelowQuorumIsPending(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	res, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Pending {
		t.Fatalf("Outcome = %v, want Pending", res.Outcome)
	}
}

func TestTallyMOfNResolvesApproved(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(vote("k2", Approve, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Approved {
		t.Fatalf("Outcome = %v, want Approved", res.Outcome)
	}
	if len(res.Approvers) != 2 {
		t.Fatalf("Approvers = %v, want 2 distinct keys", res.Approvers)
	}
}

func TestTallyHigherMConfigurable(t *testing.T) {
	tally := newTally(3)
	now := time.Now()
	for i, kid := range []string{"k1", "k2"} {
		res, err := tally.Add(vote(kid, Approve, now.Add(time.Hour)), now)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != Pending {
			t.Fatalf("after vote %d: Outcome = %v, want Pending", i, res.Outcome)
		}
	}
	res, err := tally.Add(vote("k3", Approve, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Approved {
		t.Fatalf("Outcome = %v, want Approved", res.Outcome)
	}
}

func TestTallySameKeyTwiceDoesNotDoubleCount(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now)
	if err != ErrDuplicateVote {
		t.Fatalf("err = %v, want ErrDuplicateVote", err)
	}
	if res.Outcome != Pending {
		t.Fatalf("Outcome = %v, want still Pending after a rejected duplicate", res.Outcome)
	}
}

// TestTallyTwoKeysSameOwnerCountOnce is the core of the owner-based quorum
// (spec §9): two DIFFERENT keys (different Kid) configured with the exact
// same Owner must not satisfy a 2-of-N quorum between themselves.
func TestTallyTwoKeysSameOwnerCountOnce(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	sameOwner := Owner{KeyID: "ak_shared"}
	if _, err := tally.Add(Vote{Kid: "key-a", Owner: sameOwner, Decision: Approve, Expiry: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(Vote{Kid: "key-b", Owner: sameOwner, Decision: Approve, Expiry: now.Add(time.Hour)}, now)
	if err != ErrDuplicateVote {
		t.Fatalf("err = %v, want ErrDuplicateVote (same owner, different key)", err)
	}
	if res.Outcome != Pending {
		t.Fatalf("Outcome = %v, want Pending: two keys with the same owner must count once", res.Outcome)
	}
}

// TestTallyDistinctOwnersResolve is the positive counterpart: different
// keys with genuinely distinct owners do reach quorum.
func TestTallyDistinctOwnersResolve(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(Vote{Kid: "key-a", Owner: Owner{KeyID: "ak_alice"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(Vote{Kid: "key-b", Owner: Owner{AgentID: "bob-agent"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Approved {
		t.Fatalf("Outcome = %v, want Approved: two distinct owners should reach a 2-of-N quorum", res.Outcome)
	}
}

// TestTallyRequesterOwnedKeyNeverCounts: a key whose Owner matches the
// excluded requester identity never counts, even alongside enough other
// distinct owners to otherwise meet quorum — only the other two count.
func TestTallyRequesterOwnedKeyNeverCounts(t *testing.T) {
	tally := NewTally(2, "ak_requester", "")
	now := time.Now()
	// The requester's own approver key: refused, never counted.
	res, err := tally.Add(Vote{Kid: "key-requester", Owner: Owner{KeyID: "ak_requester"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now)
	ve, ok := err.(*VerifyError)
	if !ok || ve.Code != CodeSelfApproval {
		t.Fatalf("err = %v, want SELF_APPROVAL", err)
	}
	if res.Outcome != Pending {
		t.Fatalf("Outcome = %v, want Pending (the excluded vote must not count)", res.Outcome)
	}
	// Two other, distinct owners: these two alone meet the quorum of 2.
	if _, err := tally.Add(Vote{Kid: "key-a", Owner: Owner{KeyID: "ak_alice"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	res, err = tally.Add(Vote{Kid: "key-b", Owner: Owner{AgentID: "bob-agent"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Approved || len(res.Approvers) != 2 {
		t.Fatalf("resolution = %+v, want Approved with exactly the 2 non-requester owners", res)
	}
}

// TestTallyRequesterOwnedKeyExcludedByAgentID mirrors the above for the
// agent_id side of the exclusion.
func TestTallyRequesterOwnedKeyExcludedByAgentID(t *testing.T) {
	tally := NewTally(1, "", "requester-agent")
	now := time.Now()
	_, err := tally.Add(Vote{Kid: "key-requester", Owner: Owner{AgentID: "requester-agent"}, Decision: Approve, Expiry: now.Add(time.Hour)}, now)
	ve, ok := err.(*VerifyError)
	if !ok || ve.Code != CodeSelfApproval {
		t.Fatalf("err = %v, want SELF_APPROVAL", err)
	}
}

func TestTallyRejectResolvesImmediatelyRegardlessOfQuorum(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(vote("k2", Reject, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Rejected {
		t.Fatalf("Outcome = %v, want Rejected", res.Outcome)
	}
}

func TestTallyAlreadyResolvedRefusesFurtherVotes(t *testing.T) {
	tally := newTally(1)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now); err != nil {
		t.Fatal(err)
	}
	// Approve-after-resolved.
	res, err := tally.Add(vote("k2", Approve, now.Add(time.Hour)), now)
	if err != ErrAlreadyResolved {
		t.Fatalf("err = %v, want ErrAlreadyResolved", err)
	}
	if res.Outcome != Approved {
		t.Fatalf("Outcome = %v, want the already-settled Approved to be returned", res.Outcome)
	}
	// Reject-after-resolved (approve-after-reject's mirror: reject-after-approve).
	res, err = tally.Add(vote("k3", Reject, now.Add(time.Hour)), now)
	if err != ErrAlreadyResolved {
		t.Fatalf("err = %v, want ErrAlreadyResolved", err)
	}
	if res.Outcome != Approved {
		t.Fatalf("Outcome changed after resolution: %v", res.Outcome)
	}
}

func TestTallyApproveAfterRejectIsRefused(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Reject, now.Add(time.Hour)), now); err != nil {
		t.Fatal(err)
	}
	res, err := tally.Add(vote("k2", Approve, now.Add(time.Hour)), now)
	if err != ErrAlreadyResolved {
		t.Fatalf("err = %v, want ErrAlreadyResolved", err)
	}
	if res.Outcome != Rejected {
		t.Fatalf("Outcome = %v, want Rejected to stay final", res.Outcome)
	}
}

func TestTallyExpiredVotesDoNotCount(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	// k1 votes with a vote that will have expired by the time k2 votes.
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Minute)), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	res, err := tally.Add(vote("k2", Approve, later.Add(time.Hour)), later)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Pending {
		t.Fatalf("Outcome = %v, want Pending (k1's vote should have expired)", res.Outcome)
	}
	if len(tally.Live(later)) != 1 {
		t.Fatalf("Live = %v, want exactly k2's vote", tally.Live(later))
	}
}

func TestTallySameKeyCanVoteAgainAfterItsOwnVoteExpired(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	if _, err := tally.Add(vote("k1", Approve, now.Add(time.Minute)), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour) // k1's first vote has expired
	if _, err := tally.Add(vote("k1", Approve, later.Add(time.Hour)), later); err != nil {
		t.Fatalf("k1 should be able to vote again once its earlier vote expired: %v", err)
	}
}

func TestValidateQuorum(t *testing.T) {
	cases := []struct {
		m        int
		devWorld bool
		wantErr  bool
	}{
		{1, false, true},  // below production floor
		{2, false, false}, // exactly the floor
		{3, false, false},
		{1, true, false}, // dev-world allows M=1
		{0, true, true},  // never below 1, even in dev-world
	}
	for _, c := range cases {
		err := ValidateQuorum(c.m, c.devWorld)
		if (err != nil) != c.wantErr {
			t.Fatalf("ValidateQuorum(%d, dev=%v) err = %v, wantErr %v", c.m, c.devWorld, err, c.wantErr)
		}
	}
}
