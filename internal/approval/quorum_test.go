package approval

import (
	"testing"
	"time"
)

func vote(kid, decision string, expiry time.Time) Vote {
	return Vote{Kid: kid, Decision: decision, Expiry: expiry}
}

func TestTallyBelowQuorumIsPending(t *testing.T) {
	tally := NewTally(2)
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
	tally := NewTally(2)
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
	tally := NewTally(3)
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
	tally := NewTally(2)
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

func TestTallyRejectResolvesImmediatelyRegardlessOfQuorum(t *testing.T) {
	tally := NewTally(2)
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
	tally := NewTally(1)
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
	tally := NewTally(2)
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
	tally := NewTally(2)
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
	tally := NewTally(2)
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
