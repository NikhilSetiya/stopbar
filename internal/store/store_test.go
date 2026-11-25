package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestGroupCommitIsolatesFailures: concurrent writers share transactions,
// yet each gets its own result. A writer that errs or panics writes nothing
// and gets its own error or panic back; every other writer's change is
// durable (it survives a reopen).
func TestGroupCommitIsolatesFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	bk := []byte("b")
	if err := db.Bucket(bk); err != nil {
		t.Fatal(err)
	}
	errBad := errors.New("bad write")
	const n = 200
	errs := make([]error, n)
	panics := make([]any, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { panics[i] = recover() }()
			errs[i] = db.Update(func(tx *bolt.Tx) error {
				if err := tx.Bucket(bk).Put(fmt.Appendf(nil, "k%03d", i), []byte("v")); err != nil {
					return err
				}
				switch i % 50 {
				case 7:
					return errBad
				case 13:
					panic("boom")
				}
				return nil
			})
		}()
	}
	wg.Wait()
	for i := range n {
		switch i % 50 {
		case 7:
			if !errors.Is(errs[i], errBad) || panics[i] != nil {
				t.Errorf("writer %d: err %v panic %v, want its own error", i, errs[i], panics[i])
			}
		case 13:
			if panics[i] != "boom" {
				t.Errorf("writer %d: panic %v, want its own panic", i, panics[i])
			}
		default:
			if errs[i] != nil || panics[i] != nil {
				t.Errorf("writer %d: err %v panic %v, want success", i, errs[i], panics[i])
			}
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if err := ro.View(func(tx *bolt.Tx) error {
		for i := range n {
			got := tx.Bucket(bk).Get(fmt.Appendf(nil, "k%03d", i)) != nil
			if want := i%50 != 7 && i%50 != 13; got != want {
				t.Errorf("key %d stored = %v, want %v", i, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestGroupCommitFailureFailsEveryCaller: when the group's transaction
// cannot commit (an injected failure at commit time, as a failed fsync
// would be), every caller in it gets an error and nothing is written. A
// caller is acknowledged only by a commit that succeeded.
func TestGroupCommitFailureFailsEveryCaller(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bk := []byte("b")
	if err := db.Bucket(bk); err != nil {
		t.Fatal(err)
	}
	errDisk := errors.New("fsync failed")
	db.fault = func() error { return errDisk }
	const n = 100
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bk).Put(fmt.Appendf(nil, "k%03d", i), []byte("v")) })
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, errDisk) {
			t.Errorf("writer %d: err %v, want the commit failure", i, err)
		}
	}
	db.fault = nil
	if err := db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bk).Cursor().First(); k != nil {
			t.Errorf("key %q written by a failed commit", k)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
