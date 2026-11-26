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

// TestRecordKeysSortByCreationAndLegacyKeysGo (CS-197): records are keyed by
// creation time, so they sort by it on disk whatever their (client-chosen)
// ids. A record stored under its id alone (before the ordered layout) loads,
// and is moved to the ordered key by its next write, never duplicated.
func TestRecordKeysSortByCreationAndLegacyKeysGo(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewBoltStore(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	legacy := Record{ID: "m-legacy", Count: 1, Units: "1", Created: t0, Expires: t0.Add(time.Minute), State: StateReserved}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, _ := json.Marshal(legacy)
		return tx.Bucket(boltBucket).Put([]byte(legacy.ID), b)
	}); err != nil {
		t.Fatal(err)
	}
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
	want := []string{"m-legacy/committed", "z-first/reserved", "a-second/reserved"}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] {
		t.Fatalf("on-disk order %v, want %v (by creation, legacy key replaced)", ids, want)
	}
}
