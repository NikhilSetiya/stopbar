package limiter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
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
	// Tenant and Agent own the reservation: only they may commit or release
	// it over HTTP (CS-105).
	Tenant string `json:"tenant,omitempty"`
	Agent  string `json:"agent,omitempty"`
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
// one removed) with its audit records in the same transaction. LoadBreakers
// returns every open breaker.
type Store interface {
	Put(r Record, entry *model.AuditEntry) error
	Delete(recs []Record) error
	Load() ([]Record, error)
	PutBreaker(b model.BreakerStatus, entries ...*model.AuditEntry) error
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
func (MemStore) Delete([]Record) error   { return nil }
func (MemStore) Load() ([]Record, error) { return nil, nil }

// PutBreaker refuses: every breaker change is audited, and MemStore cannot
// audit. A trip still opens in memory (failing closed); a reset is refused.
func (MemStore) PutBreaker(model.BreakerStatus, ...*model.AuditEntry) error {
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

func (s *BoltStore) PutBreaker(b model.BreakerStatus, entries ...*model.AuditEntry) error {
	if len(entries) == 0 || slices.Contains(entries, nil) || s.log == nil {
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
		for _, e := range entries {
			if err := s.log.AppendTx(tx, *e); err != nil {
				return err
			}
		}
		return nil
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

// UnitStore is a Store whose writes can join the store.Unit in ctx (CS-197).
// after(err) runs once the write has landed or failed.
type UnitStore interface {
	PutCtx(ctx context.Context, r Record, entry *model.AuditEntry, after func(error)) error
	DeleteCtx(ctx context.Context, recs []Record) // best effort compaction; never fails the unit
}

func (s *BoltStore) Put(r Record, entry *model.AuditEntry) error {
	return s.PutCtx(context.Background(), r, entry, nil)
}

// PutCtx is Put joining the unit in ctx, if any (store.DB.Write).
func (s *BoltStore) PutCtx(ctx context.Context, r Record, entry *model.AuditEntry, after func(error)) error {
	b, err := json.Marshal(r)
	if err == nil && entry != nil && s.log == nil {
		err = errors.New("limiter: no audit log configured")
	}
	if err != nil {
		if after != nil {
			after(err)
		}
		return err
	}
	return s.db.Write(ctx, func(tx *bolt.Tx) error {
		bk := tx.Bucket(boltBucket)
		// The pre-CS-197 key, if this record has one (a no-op otherwise).
		_ = bk.Delete([]byte(r.ID))
		// Keys sort by creation, so inserts append; 0.9 leaves headroom for the commit rewrite.
		bk.FillPercent = 0.9
		if err := bk.Put(recordKey(r), b); err != nil {
			return err
		}
		if entry != nil {
			return s.log.AppendTx(tx, *entry)
		}
		return nil
	}, after)
}

// recordKey is created(8 bytes, big-endian Unix ns) || id: records sort by
// creation, so new ones append at the end of the B+tree instead of dirtying
// a random leaf page each (request ids are client-chosen), and retention
// compaction deletes from the front (CS-197). Records written before this
// are keyed by id alone; Load reads both, and Put and Delete remove the old
// key.
func recordKey(r Record) []byte {
	k := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(r.ID)), uint64(r.Created.UnixNano()))
	return append(k, r.ID...)
}

func (s *BoltStore) DeleteCtx(ctx context.Context, recs []Record) {
	_ = s.db.Write(ctx, func(tx *bolt.Tx) error {
		bk := tx.Bucket(boltBucket)
		for _, r := range recs {
			_ = bk.Delete(recordKey(r))
			_ = bk.Delete([]byte(r.ID))
		}
		return nil
	}, nil)
}

func (s *BoltStore) Delete(recs []Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(boltBucket)
		for _, r := range recs {
			if err := bk.Delete(recordKey(r)); err != nil {
				return err
			}
			if err := bk.Delete([]byte(r.ID)); err != nil {
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
