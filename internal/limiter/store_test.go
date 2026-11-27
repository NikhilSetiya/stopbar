package limiter

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

func boltRig(t *testing.T, before func(*store.DB)) (*store.DB, *BoltStore) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if before != nil {
		if err := db.Bucket(boltBucket); err != nil {
			t.Fatal(err)
		}
		before(db)
	}
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewBoltStore(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	return db, s
}

func onDisk(t *testing.T, db *store.DB) []string {
	t.Helper()
	var ids []string
	_ = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(boltBucket).ForEach(func(_, v []byte) error {
			var r Record
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			ids = append(ids, r.ID+"/"+r.State)
			return nil
		})
	})
	return ids
}

// TestRecordKeysSortByCreationAndLegacyKeysMigrate (CS-197): records are
// keyed by creation time, so they sort by it on disk whatever their
// (client-chosen) ids. A record stored under its id alone (before the
// ordered layout) is moved to the ordered key once, when the store opens.
func TestRecordKeysSortByCreationAndLegacyKeysMigrate(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	legacy := Record{ID: "m-legacy", Count: 1, Units: "1", Created: t0, Expires: t0.Add(time.Minute), State: StateReserved}
	db, s := boltRig(t, func(db *store.DB) {
		_ = db.Update(func(tx *bolt.Tx) error {
			b, _ := json.Marshal(legacy)
			return tx.Bucket(boltBucket).Put([]byte(legacy.ID), b)
		})
	})
	for i, id := range []string{"z-first", "a-second"} {
		r := Record{ID: id, Count: 1, Units: "1", Created: t0.Add(time.Duration(i+1) * time.Second), Expires: t0.Add(time.Hour), State: StateReserved}
		if err := s.Put(r, nil); err != nil {
			t.Fatal(err)
		}
	}
	legacy.State = StateCommitted
	if err := s.Put(legacy, nil); err != nil {
		t.Fatal(err)
	}
	got, want := onDisk(t, db), []string{"m-legacy/committed", "z-first/reserved", "a-second/reserved"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("on-disk order %v, want %v (by creation, legacy key migrated)", got, want)
	}
}

// TestCraftedIDCannotDeleteAnotherRecord (review finding 5 on #146): a
// request id equal to another record's on-disk key (created_ns || victim id)
// must not let its write or compaction delete the victim's record.
func TestCraftedIDCannotDeleteAnotherRecord(t *testing.T) {
	db, s := boltRig(t, nil)
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	victim := Record{ID: "victim", Count: 1, Units: "1", Created: t0, Expires: t0.Add(time.Hour), State: StateCommitted}
	if err := s.Put(victim, nil); err != nil {
		t.Fatal(err)
	}
	crafted := Record{ID: string(recordKey(victim)), Count: 1, Units: "1", Created: t0.Add(time.Second), Expires: t0.Add(time.Hour), State: StateReserved}
	if err := s.Put(crafted, nil); err != nil {
		t.Fatal(err)
	}
	s.DeleteCtx(bg, []Record{crafted})
	if got := onDisk(t, db); len(got) != 1 || got[0] != "victim/committed" {
		t.Fatalf("on disk %v, want the victim's record untouched", got)
	}
}
