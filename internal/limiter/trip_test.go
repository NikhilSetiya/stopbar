package limiter

import (
	"errors"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

type blockingBreakerStore struct {
	MemStore
	entered, release chan struct{}
}

func (s blockingBreakerStore) PutBreaker(model.BreakerStatus, ...*model.AuditEntry) error {
	close(s.entered)
	<-s.release
	return nil
}

// TestTripDoesNotHoldTheLimiterAcrossItsWrite (review on #146, minor): while
// a breaker trip is being written, the limiter lock is free and the breaker
// is already open, so other calls for the tenant are refused at once instead
// of queueing behind the fsync.
func TestTripDoesNotHoldTheLimiterAcrossItsWrite(t *testing.T) {
	st := blockingBreakerStore{entered: make(chan struct{}), release: make(chan struct{})}
	l, err := New(Config{Store: st, Clock: newClock().Now, Rules: []Rule{{Scope: ScopeTenant, Window: "1h", MaxUSD: "10", CircuitBreaker: true}}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Reserve(bg, "big", req(walletA, dest, "50", "1", true), time.Minute, nil) }()
	<-st.entered
	open := make(chan bool, 1)
	go func() { o, _ := l.CircuitOpen(bg, "acme"); open <- o }()
	select {
	case o := <-open:
		if !o {
			t.Fatal("breaker not open while its trip is being written")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CircuitOpen blocked behind the trip's write: the limiter lock is held across the fsync")
	}
	close(st.release)
	if err := <-done; !errors.Is(err, engine.ErrCircuitOpen) {
		t.Fatalf("Reserve: %v, want CIRCUIT_OPEN", err)
	}
}
