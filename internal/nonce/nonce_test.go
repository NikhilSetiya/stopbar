package nonce

import (
	"path/filepath"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ ns atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *clock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

func newClock() *clock {
	c := &clock{}
	c.ns.Store(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func TestConsumeOnceUntilExpiry(t *testing.T) {
	c := newClock()
	s := NewMemory(c.Now)
	k := Key("acme", "agent", "n1")
	until := c.Now().Add(time.Minute)
	if fresh, err := s.Consume(k, until); !fresh || err != nil {
		t.Fatalf("first: %v %v", fresh, err)
	}
	if fresh, _ := s.Consume(k, until); fresh {
		t.Fatal("second consume reported fresh")
	}
	c.Advance(time.Minute - time.Nanosecond)
	if fresh, _ := s.Consume(k, until); fresh {
		t.Fatal("forgotten before retention ended")
	}
	c.Advance(time.Nanosecond)
	if s.Len() != 0 {
		t.Fatalf("not pruned at retention end: %d", s.Len())
	}
}

func TestKeyQuoting(t *testing.T) {
	if Key("a/b", "c", "n") == Key("a", "b/c", "n") || Key("a", "b", "c/d") == Key("a", "b/c", "d") {
		t.Fatal("keys collide")
	}
}

func TestConcurrentConsumeExactlyOne(t *testing.T) {
	s := NewMemory(newClock().Now)
	var fresh atomic.Int64
	var wg sync.WaitGroup
	for range 1000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.Consume(Key("t", "a", "same"), time.Now().Add(time.Hour)); ok && err == nil {
				fresh.Add(1)
			}
		}()
	}
	wg.Wait()
	if fresh.Load() != 1 {
		t.Fatalf("%d goroutines consumed the same nonce", fresh.Load())
	}
}

// A restart inside the retention window must not reopen a replay.
func TestBoltRestartKeepsNonces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	c := newClock()
	open := func() (*Store, *store.DB) {
		db, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(db, "nonces", nil, c.Now)
		if err != nil {
			t.Fatal(err)
		}
		return s, db
	}
	s, db := open()
	k := Key("acme", "agent", "n1")
	if fresh, err := s.Consume(k, c.Now().Add(6*time.Minute)); !fresh || err != nil {
		t.Fatal(fresh, err)
	}
	if fresh, _ := s.Consume(Key("acme", "agent", "old"), c.Now().Add(time.Second)); !fresh {
		t.Fatal("old")
	}
	_ = db.Close()

	c.Advance(5 * time.Minute)
	s, db = open()
	defer func() { _ = db.Close() }()
	if fresh, _ := s.Consume(k, c.Now().Add(time.Minute)); fresh {
		t.Fatal("restart reopened a replay")
	}
	if s.Len() != 1 {
		t.Fatalf("expired nonce survived restart: %d retained", s.Len())
	}
}

// The accepted request is audited if and only if its nonce is spent.
func TestConsumeWithAuditsAtomically(t *testing.T) {
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(db, "nonces", lg, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &model.AuditEntry{Type: model.AuditRequest, Body: map[string]any{"request_id": "r1"}}
	if fresh, err := s.ConsumeWith(Key("t", "a", "n"), time.Now().Add(time.Minute), e); !fresh || err != nil {
		t.Fatal(fresh, err)
	}
	if fresh, _ := s.ConsumeWith(Key("t", "a", "n"), time.Now().Add(time.Minute), e); fresh {
		t.Fatal("replay")
	}
	if recs, _ := audit.Records(db, 1, 0); len(recs) != 1 || recs[0].Type != model.AuditRequest {
		t.Fatalf("records %+v: a replay must not be recorded as a request", recs)
	}
	unaudited, err := Open(db, "other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unaudited.ConsumeWith(Key("t", "a", "x"), time.Now().Add(time.Minute), e); err == nil {
		t.Fatal("an audited consume on a store without a log must fail closed")
	}
}
