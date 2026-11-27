package nonce

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/store"
)

// TestDuplicateEntriesNeverReopenAReplay (review finding 3 on #146): a key
// can be on disk twice, with an earlier and a later expiry (a compaction that
// did not land, then the key consumed again; after a clock rollback both are
// live at open). The earlier expiry must not end the later one: once it
// passes, the key is still refused until the later expiry.
func TestDuplicateEntriesNeverReopenAReplay(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	c := newClock()
	k := Key("acme", "agent", "n")
	t1, t2 := c.Now().Add(time.Minute), c.Now().Add(time.Hour)
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("nonces"))
		if err != nil {
			return err
		}
		for _, u := range []time.Time{t1, t2} {
			if err := b.Put(diskKey(k, u), v2Mark); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(db, "nonces", nil, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * time.Minute) // past t1, before t2
	if fresh, err := s.Consume(k, c.Now().Add(time.Hour)); fresh || err != nil {
		t.Fatalf("Consume after the earlier expiry: fresh=%v err=%v, want refused until %s", fresh, err, t2)
	}
	if s.Len() != 1 {
		t.Fatalf("%d keys retained, want 1", s.Len())
	}
}
