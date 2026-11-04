package limiter

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Reservation states.
const (
	StateReserved  = "reserved"
	StateCommitted = "committed"
	StateReleased  = "released"
)

// Record is the durable form of one reservation. Expiry is not a state: a
// reserved record past Expires is simply not counted.
type Record struct {
	ID          string     `json:"id"`
	Keys        []string   `json:"keys"`
	USDMicro    string     `json:"usd_micro,omitempty"` // empty: unpriced
	Count       int64      `json:"count"`
	Units       string     `json:"units"`
	Created     time.Time  `json:"created"`
	Expires     time.Time  `json:"expires"`
	State       string     `json:"state"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
	TxRef       string     `json:"tx_ref,omitempty"`
}

func fromRecord(r Record) (*entry, error) {
	amt := amount{count: r.Count, units: new(big.Int)}
	if r.USDMicro != "" {
		v, ok := new(big.Int).SetString(r.USDMicro, 10)
		if !ok {
			return nil, fmt.Errorf("bad usd_micro %q", r.USDMicro)
		}
		amt.usd = v
	}
	if _, ok := amt.units.SetString(r.Units, 10); !ok {
		return nil, fmt.Errorf("bad units %q", r.Units)
	}
	switch r.State {
	case StateReserved, StateCommitted, StateReleased:
	default:
		return nil, fmt.Errorf("bad state %q", r.State)
	}
	return &entry{Record: r, amt: amt}, nil
}

// Store persists reservation records. Put must be durable when it returns.
type Store interface {
	Put(r Record) error
	Delete(ids []string) error
	Load() ([]Record, error)
}

// MemStore keeps nothing: state lives only in the Limiter (tests, dev).
type MemStore struct{}

func (MemStore) Put(Record) error        { return nil }
func (MemStore) Delete([]string) error   { return nil }
func (MemStore) Load() ([]Record, error) { return nil, nil }

var boltBucket = []byte("limiter_reservations_v1")

// BoltStore persists records in a bbolt file. bbolt takes an exclusive file
// lock, so two processes cannot share one limiter state by accident (that
// needs the Redis store, CS-306).
type BoltStore struct{ db *bolt.DB }

// OpenBolt opens or creates the store at path.
func OpenBolt(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("limiter: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(boltBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Close() error { return s.db.Close() }

func (s *BoltStore) Put(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(boltBucket).Put([]byte(r.ID), b) })
}

func (s *BoltStore) Delete(ids []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(boltBucket)
		for _, id := range ids {
			if err := bk.Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BoltStore) Load() ([]Record, error) {
	var out []Record
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(boltBucket).ForEach(func(k, v []byte) error {
			var r Record
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("record %q: %w", k, err)
			}
			out = append(out, r)
			return nil
		})
	})
	return out, err
}
