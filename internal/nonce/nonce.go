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
	"context"
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
	mu    sync.Mutex
	clock func() time.Time
	until map[string]time.Time
	exp   expHeap
	// pending holds keys whose write is in flight. They count as seen, so a
	// concurrent duplicate is refused while the store lock is not held across
	// the fsync; a failed write removes the key again.
	pending map[string]bool
	db      *store.DB // nil: memory only
	bucket  []byte
	log     *audit.Log // set: ConsumeWith records entries atomically
}

// NewMemory returns a store that forgets on restart and records no audit
// entries. Unit tests only: stopbard always uses Open on the state file.
func NewMemory(clock func() time.Time) *Store {
	if clock == nil {
		clock = time.Now
	}
	return &Store{clock: clock, until: map[string]time.Time{}, pending: map[string]bool{}}
}

// On disk a nonce is the key until(8 bytes, big-endian Unix ns) || nonce key,
// with value v2Mark. Keys therefore sort by expiry, so inserts append at the
// end of the B+tree (no random leaf page per insert, CS-197) and expired
// entries are deleted from the front. Entries written before that (key: the
// nonce key, value: until) are rewritten once by Open.
var v2Mark = []byte{2}

func diskKey(key string, until time.Time) []byte {
	k := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(key)), uint64(until.UnixNano()))
	return append(k, key...)
}

// Open uses bucket in the shared state file and loads unexpired nonces. With
// a log, ConsumeWith writes its audit entry in the same transaction as the
// nonce: an accepted request is recorded if and only if its nonce is spent.
func Open(db *store.DB, bucket string, log *audit.Log, clock func() time.Time) (*Store, error) {
	s := NewMemory(clock)
	s.db, s.bucket, s.log = db, []byte(bucket), log
	now := s.clock()
	type live struct {
		key   string
		until time.Time
	}
	var keep []live
	err := db.Update(func(tx *bolt.Tx) error {
		var expired [][]byte
		keep = keep[:0] // the store may run this more than once
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		var legacy []live
		if err := b.ForEach(func(k, v []byte) error {
			var key string
			var until time.Time
			switch {
			case len(v) == 1 && v[0] == v2Mark[0] && len(k) > 8:
				key, until = string(k[8:]), time.Unix(0, int64(binary.BigEndian.Uint64(k[:8])))
			case len(v) == 8: // written before CS-197: rewrite in the ordered form
				key, until = string(k), time.Unix(0, int64(binary.BigEndian.Uint64(v)))
				expired = append(expired, append([]byte(nil), k...))
				if now.Before(until) {
					legacy = append(legacy, live{key, until})
				}
				return nil
			default:
				return fmt.Errorf("nonce: corrupt entry %q", k)
			}
			if !now.Before(until) {
				expired = append(expired, append([]byte(nil), k...))
				return nil
			}
			keep = append(keep, live{key, until})
			return nil
		}); err != nil {
			return err
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		for _, l := range legacy {
			if err := b.Put(diskKey(l.key, l.until), v2Mark); err != nil {
				return err
			}
		}
		keep = append(keep, legacy...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// One entry per key, the latest expiry: a key can be on disk twice (a
	// best-effort compaction that did not land, then the key consumed again),
	// and the earlier expiry must not end the later one (review finding 3).
	latest := map[string]time.Time{}
	for _, l := range keep {
		if u, ok := latest[l.key]; !ok || l.until.After(u) {
			latest[l.key] = l.until
		}
	}
	for k, u := range latest {
		s.insert(k, u)
	}
	return s, nil
}

// Consume records key until `until` and reports whether it was unseen. An
// error means the nonce state is unknown, and the caller must fail closed.
func (s *Store) Consume(key string, until time.Time) (fresh bool, err error) {
	return s.ConsumeWith(context.Background(), key, until, nil)
}

// ConsumeCtx is Consume under ctx: with a store.Unit in ctx the write joins
// that unit (the signer adapter's spent-token check, CS-197).
func (s *Store) ConsumeCtx(ctx context.Context, key string, until time.Time) (fresh bool, err error) {
	return s.ConsumeWith(ctx, key, until, nil)
}

// ConsumeWith is Consume plus an audit entry written in the same
// transaction as the nonce (when the store has a log).
//
// The key is marked pending first and the store lock is not held across the
// durable write: a concurrent consume of the same key sees it as seen
// (refused), and other keys share the fsync (store.DB.Update). Without a
// unit in ctx it returns fresh only once the write is durable. With one
// (store.Unit, the gateway's evaluation) the write joins the unit and fresh
// is provisional: the key stays pending until the unit commits, and the
// gateway answers nothing before that. If the write fails the key is
// released again.
func (s *Store) ConsumeWith(ctx context.Context, key string, until time.Time, entry *model.AuditEntry) (fresh bool, err error) {
	if s.db != nil && entry != nil && s.log == nil {
		return false, errors.New("nonce: no audit log configured for an audited consume")
	}
	if entry, err = audit.Prepare(entry); err != nil { // the body as it is now, not at unit commit
		return false, fmt.Errorf("nonce: audit entry: %w", err)
	}
	s.mu.Lock()
	gone := s.prune(s.clock())
	_, seen := s.until[key]
	if seen || s.pending[key] {
		s.mu.Unlock()
		s.forget(ctx, gone)
		return false, nil
	}
	if s.db == nil {
		s.insert(key, until)
		s.mu.Unlock()
		return true, nil
	}
	s.pending[key] = true
	s.mu.Unlock()
	s.forget(ctx, gone)

	err = s.db.Write(ctx, func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		b.FillPercent = 1 // keys sort by expiry: inserts append, so fill pages (CS-197)
		if err := b.Put(diskKey(key, until), v2Mark); err != nil {
			return err
		}
		if entry != nil {
			return s.log.AppendTx(tx, *entry)
		}
		return nil
	}, func(err error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.pending, key)
		if err == nil {
			s.insert(key, until)
		}
	})
	if err != nil {
		return false, fmt.Errorf("nonce: persist: %w", err)
	}
	return true, nil
}

// Len reports how many nonces are retained (tests, metrics).
func (s *Store) Len() int {
	s.mu.Lock()
	gone := s.prune(s.clock())
	n := len(s.until)
	s.mu.Unlock()
	s.forget(context.Background(), gone)
	return n
}

func (s *Store) insert(key string, until time.Time) {
	s.until[key] = until
	heap.Push(&s.exp, item{key, until})
}

// prune drops expired keys from memory (s.mu held) and returns them for
// forget, which deletes them from the file after the lock is released.
func (s *Store) prune(now time.Time) []item {
	var gone []item
	for len(s.exp) > 0 && !now.Before(s.exp[0].until) {
		it := heap.Pop(&s.exp).(item)
		if u, ok := s.until[it.key]; ok && u.Equal(it.until) { // a stale heap item never ends a live key
			delete(s.until, it.key)
		}
		gone = append(gone, it) // its on-disk entry (keyed by this expiry) is expired either way
	}
	return gone
}

// forget compacts expired keys out of the file, in the caller's unit when
// there is one (no fsync of its own). Best effort, so it never fails the
// unit: Open drops expired entries on load as well. The on-disk key includes
// the expiry, so a key consumed again meanwhile (a later expiry) is a
// different entry and is never deleted here.
func (s *Store) forget(ctx context.Context, gone []item) {
	if s.db != nil && len(gone) > 0 {
		_ = s.db.Write(ctx, func(tx *bolt.Tx) error {
			b := tx.Bucket(s.bucket)
			for _, it := range gone {
				_ = b.Delete(diskKey(it.key, it.until))
			}
			return nil
		}, nil)
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
