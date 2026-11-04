// Package nonce is the single-use store behind the gateway's replay check
// (CS-102, LLD §4) and the signer adapter's spent-token check.
//
// Consume is an atomic check-and-set: of any number of concurrent calls with
// the same key, exactly one sees fresh=true. A nonce is recorded durably
// (bbolt) before Consume reports it fresh, so a restart cannot reopen a
// replay window. A failed write reports an error, and the gateway fails
// closed. Expired entries are pruned via a heap, so the cost is proportional
// to what expired.
package nonce

import (
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// Key scopes a nonce to (tenant, agent): one tenant cannot burn another's
// nonces. Components are quoted so no chosen value can make two keys collide.
func Key(tenant, agent, nonce string) string {
	return strconv.Quote(tenant) + "/" + strconv.Quote(agent) + "/" + strconv.Quote(nonce)
}

// Store records consumed nonces until their retention ends.
type Store struct {
	mu     sync.Mutex
	clock  func() time.Time
	until  map[string]time.Time
	exp    expHeap
	db     *store.DB // nil: memory only
	bucket []byte
	log    *audit.Log // set: ConsumeWith records entries atomically
}

// NewMemory returns a store that forgets on restart and records no audit
// entries. Unit tests only: stopbard always uses Open on the state file.
func NewMemory(clock func() time.Time) *Store {
	if clock == nil {
		clock = time.Now
	}
	return &Store{clock: clock, until: map[string]time.Time{}}
}

// Open uses bucket in the shared state file and loads unexpired nonces. With
// a log, ConsumeWith writes its audit entry in the same transaction as the
// nonce: an accepted request is recorded if and only if its nonce is spent.
func Open(db *store.DB, bucket string, log *audit.Log, clock func() time.Time) (*Store, error) {
	s := NewMemory(clock)
	s.db, s.bucket, s.log = db, []byte(bucket), log
	now := s.clock()
	var expired [][]byte
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		if err := b.ForEach(func(k, v []byte) error {
			if len(v) != 8 {
				return fmt.Errorf("nonce: corrupt entry %q", k)
			}
			until := time.Unix(0, int64(binary.BigEndian.Uint64(v)))
			if !now.Before(until) {
				expired = append(expired, append([]byte(nil), k...))
				return nil
			}
			s.insert(string(k), until)
			return nil
		}); err != nil {
			return err
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Consume records key until `until` and reports whether it was unseen. An
// error means the nonce state is unknown, and the caller must fail closed.
func (s *Store) Consume(key string, until time.Time) (fresh bool, err error) {
	return s.ConsumeWith(key, until, nil)
}

// ConsumeWith is Consume plus an audit entry written in the same
// transaction as the nonce (when the store has a log).
func (s *Store) ConsumeWith(key string, until time.Time, entry *model.AuditEntry) (fresh bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.prune(now)
	if _, seen := s.until[key]; seen {
		return false, nil
	}
	if s.db != nil {
		v := make([]byte, 8)
		binary.BigEndian.PutUint64(v, uint64(until.UnixNano()))
		if entry != nil && s.log == nil {
			return false, errors.New("nonce: no audit log configured for an audited consume")
		}
		if err := s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.Bucket(s.bucket).Put([]byte(key), v); err != nil {
				return err
			}
			if entry != nil {
				return s.log.AppendTx(tx, *entry)
			}
			return nil
		}); err != nil {
			return false, fmt.Errorf("nonce: persist: %w", err)
		}
	}
	s.insert(key, until)
	return true, nil
}

// Len reports how many nonces are retained (tests, metrics).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(s.clock())
	return len(s.until)
}

func (s *Store) insert(key string, until time.Time) {
	s.until[key] = until
	heap.Push(&s.exp, item{key, until})
}

func (s *Store) prune(now time.Time) {
	var gone []string
	for len(s.exp) > 0 && !now.Before(s.exp[0].until) {
		it := heap.Pop(&s.exp).(item)
		delete(s.until, it.key)
		gone = append(gone, it.key)
	}
	if s.db != nil && len(gone) > 0 {
		// Best effort: OpenBolt drops expired entries on load as well.
		_ = s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(s.bucket)
			for _, k := range gone {
				if err := b.Delete([]byte(k)); err != nil {
					return err
				}
			}
			return nil
		})
	}
}

type item struct {
	key   string
	until time.Time
}

type expHeap []item

func (h expHeap) Len() int           { return len(h) }
func (h expHeap) Less(i, j int) bool { return h[i].until.Before(h[j].until) }
func (h expHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expHeap) Push(x any)        { *h = append(*h, x.(item)) }
func (h *expHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}
