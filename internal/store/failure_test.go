package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestPanickingOpStillSettlesTheUnit (review finding 2): an op that panics
// inside a unit must not skip the rollback callbacks. Every callback runs
// once, with an error, before the panic reaches the caller; otherwise a
// nonce would stay pending and a limiter entry would stay settling forever.
func TestPanickingOpStillSettlesTheUnit(t *testing.T) {
	db := unitDB(t)
	u := db.NewUnit()
	ctx := WithUnit(context.Background(), u)
	var errs []error
	collect := func(err error) { errs = append(errs, err) }
	var ids []int
	_ = db.Write(ctx, put("a", &ids), collect)
	_ = db.Write(ctx, func(*bolt.Tx) error { panic("boom") }, collect)
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Fatalf("recovered %v, want the op's panic re-raised", p)
			}
		}()
		_ = u.Commit()
	}()
	if len(errs) != 2 || errs[0] == nil || errs[1] == nil {
		t.Fatalf("callbacks %v, want both run with an error", errs)
	}
	empty(t, db, "by a unit whose op panicked")

	// The same holds for a write outside a unit.
	var got error
	called := 0
	func() {
		defer func() { _ = recover() }()
		_ = db.Write(context.Background(), func(*bolt.Tx) error { panic("boom") }, func(err error) { called++; got = err })
	}()
	if called != 1 || got == nil {
		t.Fatalf("standalone write: callback ran %d times with %v", called, got)
	}
}

// TestFailedCommitBreaksTheStore (review finding 6): a failed commit (or
// fsync) is ambiguous, so it is never retried: every writer in the group
// fails, no write is re-run, and the store refuses all later writes until
// it is re-opened.
func TestFailedCommitBreaksTheStore(t *testing.T) {
	db := unitDB(t)
	errDisk := errors.New("fsync failed")
	var mu sync.Mutex
	runs := map[string]int{}
	db.SetFaultForTest(func() error { return errDisk })
	var wg sync.WaitGroup
	for _, k := range []string{"a", "b", "c", "d"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.Update(func(tx *bolt.Tx) error {
				mu.Lock()
				runs[k]++
				mu.Unlock()
				return tx.Bucket([]byte("b")).Put([]byte(k), []byte("v"))
			})
			if !errors.Is(err, ErrBroken) || !errors.Is(err, errDisk) {
				t.Errorf("%s: %v, want ErrBroken wrapping the commit error", k, err)
			}
		}()
	}
	wg.Wait()
	for k, n := range runs {
		if n != 1 {
			t.Errorf("%s ran %d times; a failed commit must not be retried", k, n)
		}
	}
	db.SetFaultForTest(nil)
	if err := db.Update(func(*bolt.Tx) error { return nil }); !errors.Is(err, ErrBroken) {
		t.Fatalf("write after a failed commit: %v, want ErrBroken", err)
	}
	if !errors.Is(db.Err(), ErrBroken) {
		t.Fatalf("Err() = %v", db.Err())
	}
}

// TestAbandonedUnit (CS-197): an abandoned unit whose transaction has not
// passed its writes fails with ErrAbandoned and writes nothing (and does not
// break the store); one that was already committing (stalled after its
// writes, as in a slow fsync) still lands, and Commit reports nil so the
// caller knows to undo it.
func TestAbandonedUnit(t *testing.T) {
	t.Run("before commit: nothing lands", func(t *testing.T) {
		db := unitDB(t)
		u := db.NewUnit()
		var ids []int
		var got error
		_ = db.Write(WithUnit(context.Background(), u), put("a", &ids), func(err error) { got = err })
		u.Abandon()
		if err := u.Commit(); !errors.Is(err, ErrAbandoned) || !errors.Is(got, ErrAbandoned) {
			t.Fatalf("Commit %v, callback %v, want ErrAbandoned", err, got)
		}
		empty(t, db, "by an abandoned unit")
		if db.Err() != nil {
			t.Fatalf("an abandoned unit broke the store: %v", db.Err())
		}
	})
	t.Run("while committing: it lands", func(t *testing.T) {
		db := unitDB(t)
		passed, release := make(chan struct{}), make(chan struct{})
		db.SetFaultForTest(func() error { close(passed); <-release; return nil })
		u := db.NewUnit()
		var ids []int
		_ = db.Write(WithUnit(context.Background(), u), put("a", &ids), nil)
		done := make(chan error, 1)
		go func() { done <- u.Commit() }()
		<-passed // past the abandon check, stuck "in fsync"
		u.Abandon()
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("Commit %v, want nil (it landed)", err)
		}
		_ = db.View(func(tx *bolt.Tx) error {
			if tx.Bucket([]byte("b")).Get([]byte("a")) == nil {
				t.Error("landed unit not on disk")
			}
			return nil
		})
	})
}
