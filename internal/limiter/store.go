package limiter

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
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

// Store persists reservation records. Put must be durable when it returns,
// and when entry is non-nil it must write the audit record in the same
// transaction as r: both durable, or neither.
//
// PutBreaker stores a tenant's circuit breaker (an open one is kept, a closed
// one removed) with its audit record in the same transaction. LoadBreakers
// returns every open breaker.
type Store interface {
	Put(r Record, entry *model.AuditEntry) error
	Delete(ids []string) error
	Load() ([]Record, error)
	PutBreaker(b model.BreakerStatus, entry *model.AuditEntry) error
	LoadBreakers() ([]model.BreakerStatus, error)
}

// MemStore keeps nothing: state lives only in the Limiter (unit tests). It
// cannot audit, so it refuses a Put that carries an audit entry rather than
// silently dropping the record.
type MemStore struct{}

func (MemStore) Put(_ Record, entry *model.AuditEntry) error {
	if entry != nil {
		return errors.New("limiter: MemStore cannot record audit entries")
	}
	return nil
}
func (MemStore) Delete([]string) error   { return nil }
func (MemStore) Load() ([]Record, error) { return nil, nil }

// PutBreaker refuses: every breaker change is audited, and MemStore cannot
// audit. A trip still opens in memory (failing closed); a reset is refused.
func (MemStore) PutBreaker(model.BreakerStatus, *model.AuditEntry) error {
	return errors.New("limiter: MemStore cannot record circuit breaker changes")
}
func (MemStore) LoadBreakers() ([]model.BreakerStatus, error) { return nil, nil }

var (
	boltBucket    = []byte("limiter_reservations_v1")
	breakerBucket = []byte("limiter_breakers_v1")
)

// BoltStore keeps records in the shared state file next to the audit log.
type BoltStore struct {
	db  *store.DB
	log *audit.Log
}

// NewBoltStore uses db's limiter bucket and appends audit entries to log in
// the same transaction.
func NewBoltStore(db *store.DB, log *audit.Log) (*BoltStore, error) {
	for _, b := range [][]byte{boltBucket, breakerBucket} {
		if err := db.Bucket(b); err != nil {
			return nil, err
		}
	}
	return &BoltStore{db: db, log: log}, nil
}

func (s *BoltStore) PutBreaker(b model.BreakerStatus, entry *model.AuditEntry) error {
	if entry == nil || s.log == nil {
		return errors.New("limiter: circuit breaker changes must be audited")
	}
	v, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(breakerBucket)
		if b.Open {
			err = bk.Put([]byte(b.Tenant), v)
		} else {
			err = bk.Delete([]byte(b.Tenant))
		}
		if err != nil {
			return err
		}
		return s.log.AppendTx(tx, *entry)
	})
}

func (s *BoltStore) LoadBreakers() ([]model.BreakerStatus, error) {
	var out []model.BreakerStatus
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(breakerBucket).ForEach(func(k, v []byte) error {
			var b model.BreakerStatus
			if err := json.Unmarshal(v, &b); err != nil {
				return fmt.Errorf("breaker %q: %w", k, err)
			}
			if !b.Open || b.Tenant != string(k) {
				return fmt.Errorf("breaker %q: stored record is not an open breaker for that tenant", k)
			}
			out = append(out, b)
			return nil
		})
	})
	return out, err
}

func (s *BoltStore) Put(r Record, entry *model.AuditEntry) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if entry != nil && s.log == nil {
		return errors.New("limiter: no audit log configured")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(boltBucket).Put([]byte(r.ID), b); err != nil {
			return err
		}
		if entry != nil {
			return s.log.AppendTx(tx, *entry)
		}
		return nil
	})
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
