package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func unitDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Bucket([]byte("b")); err != nil {
		t.Fatal(err)
	}
	return db
}

func put(k string, txIDs *[]int) Op {
	return func(tx *bolt.Tx) error {
		*txIDs = append(*txIDs, tx.ID())
		return tx.Bucket([]byte("b")).Put([]byte(k), []byte("v"))
	}
}

func empty(t *testing.T, db *DB, why string) {
	t.Helper()
	_ = db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket([]byte("b")).Cursor().First(); k != nil {
			t.Errorf("%q written %s", k, why)
		}
		return nil
	})
}

// TestUnitIsOneTransaction: every write that joins a unit lands in the same
// bbolt transaction, nothing is written before Commit, and the after
// callbacks run last first, once.
func TestUnitIsOneTransaction(t *testing.T) {
	db := unitDB(t)
	u := db.NewUnit()
	ctx := WithUnit(context.Background(), u)
	var ids []int
	var order []string
	for _, k := range []string{"nonce", "reserve", "commit"} {
		if err := db.Write(ctx, put(k, &ids), func(err error) {
			if err != nil {
				t.Errorf("%s: %v", k, err)
			}
			order = append(order, k)
		}); err != nil {
			t.Fatal(err)
		}
	}
	empty(t, db, "before Commit")
	if err := u.Commit(); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("transaction ids %v, want one transaction", ids)
	}
	if !slices.Equal(order, []string{"commit", "reserve", "nonce"}) {
		t.Fatalf("after order %v", order)
	}
	if err := u.Commit(); err != nil || len(order) != 3 {
		t.Fatalf("second Commit: %v, %d callbacks", err, len(order))
	}
}

// TestUnitFailureWritesNothing: one failing write fails the whole unit;
// every callback gets the error and no write of the unit is on disk.
func TestUnitFailureWritesNothing(t *testing.T) {
	db := unitDB(t)
	u := db.NewUnit()
	ctx := WithUnit(context.Background(), u)
	var ids []int
	var errs []error
	errBad := errors.New("bad")
	collect := func(err error) { errs = append(errs, err) }
	_ = db.Write(ctx, put("a", &ids), collect)
	_ = db.Write(ctx, func(*bolt.Tx) error { return errBad }, collect)
	_ = db.Write(ctx, put("c", &ids), collect)
	if err := u.Commit(); !errors.Is(err, errBad) {
		t.Fatalf("Commit: %v", err)
	}
	if len(errs) != 3 || slices.ContainsFunc(errs, func(e error) bool { return !errors.Is(e, errBad) }) {
		t.Fatalf("callbacks got %v", errs)
	}
	empty(t, db, "by a failed unit")
}

// TestUnitCommitFailureFailsEveryWrite: a failed commit (as a failed fsync
// would be) fails every write of the unit, and nothing is on disk.
func TestUnitCommitFailureFailsEveryWrite(t *testing.T) {
	db := unitDB(t)
	errDisk := errors.New("fsync failed")
	db.fault = func() error { return errDisk }
	u := db.NewUnit()
	ctx := WithUnit(context.Background(), u)
	var ids []int
	var errs []error
	for _, k := range []string{"a", "b"} {
		_ = db.Write(ctx, put(k, &ids), func(err error) { errs = append(errs, err) })
	}
	if err := u.Commit(); !errors.Is(err, errDisk) || len(errs) != 2 || !errors.Is(errs[0], errDisk) || !errors.Is(errs[1], errDisk) {
		t.Fatalf("Commit %v, callbacks %v", err, errs)
	}
	db.fault = nil
	empty(t, db, "by a failed commit")
}

// TestWriteOutsideOrAfterUnit: without a unit, or after the unit committed
// (a component that outlived its stage timeout), a write runs on its own
// at once: nothing is dropped.
func TestWriteOutsideOrAfterUnit(t *testing.T) {
	db := unitDB(t)
	var ids []int
	called := 0
	if err := db.Write(context.Background(), put("x", &ids), func(error) { called++ }); err != nil || called != 1 {
		t.Fatalf("no unit: %v, %d callbacks", err, called)
	}
	u := db.NewUnit()
	ctx := WithUnit(context.Background(), u)
	if err := u.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, put("late", &ids), func(error) { called++ }); err != nil || called != 2 {
		t.Fatalf("late: %v, %d callbacks", err, called)
	}
	_ = db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("b")).Get([]byte("late")) == nil {
			t.Error("late write dropped")
		}
		return nil
	})
}
