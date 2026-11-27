package limiter

import (
	"errors"
	"testing"
	"time"
)

// TestVoidReleasesEvenACommittedReservation (CS-197): Void frees the capacity
// of a reservation whose evaluation landed after the gateway answered
// FAIL_CLOSED_STORE, even if the gatekeeper had committed it (the signed tx
// never left stopbard). Release still refuses a committed one. Void of an
// unknown or already released ID is a no-op.
func TestVoidReleasesEvenACommittedReservation(t *testing.T) {
	c := newClock()
	l := newLimiter(t, c, Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "100"})
	probe := req(walletA, dest, "", "", true)
	if err := l.Reserve(bg, "r1", req(walletA, dest, "60", "1", true), time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Commit(bg, "r1", "0x1", nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(bg, "r1", nil); !errors.Is(err, ErrAlreadyCommitted) {
		t.Fatalf("Release of a committed reservation: %v", err)
	}
	if err := l.Void(bg, "r1", nil); err != nil {
		t.Fatal(err)
	}
	if got := usd(t, l, probe, ScopeWallet); got != "0" {
		t.Fatalf("usage %s after Void, want 0", got)
	}
	for _, id := range []string{"r1", "unknown"} {
		if err := l.Void(bg, id, nil); err != nil {
			t.Fatalf("Void(%s) again: %v, want a no-op", id, err)
		}
	}
}
