// Package store is Stopbar's durable state: one bbolt file holding the
// limiter, nonce, spent-token and audit buckets. Sharing one file is what
// lets an audit record be written in the same transaction as the state
// change it describes (LLD §11): either both are durable or neither is.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DB is the shared state file. bbolt serialises write transactions and takes
// an exclusive file lock, so two processes cannot share one state by accident.
type DB struct {
	bolt *bolt.DB
	temp string // set when the file lives in a temporary directory

	qmu    sync.Mutex // guards queue
	queue  []*call
	commit chan struct{} // the commit slot (capacity 1): held while a group commits
	fault  func() error  // tests only: fails each transaction as a failed commit would
}

// Op is a write that joins a caller's transaction (e.g. an audit append).
// It must change nothing outside tx: Update may run it more than once (see
// Update), and only the run whose transaction commits counts.
type Op func(tx *bolt.Tx) error

type call struct {
	fn   Op
	done chan result
}

type result struct {
	err   error
	panic any
}

// Open opens or creates the state file at path.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return &DB{bolt: b, commit: make(chan struct{}, 1)}, nil
}

// OpenReadOnly opens an existing state file without writing to it (for
// offline verification). It fails while a process holds the file.
func OpenReadOnly(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	return &DB{bolt: b, commit: make(chan struct{}, 1)}, nil
}

// OpenTemp opens a state file in a fresh temporary directory that Close
// removes: same code path and same atomicity, no durability across restarts.
func OpenTemp() (*DB, error) {
	dir, err := os.MkdirTemp("", "stopbar-state-")
	if err != nil {
		return nil, err
	}
	db, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	db.temp = dir
	return db, nil
}

// Update runs fn in a write transaction and returns once that transaction
// is committed and fsynced (or failed): every caller still gets a durable
// write, and each fn's state change and audit record stay in one
// transaction.
//
// Concurrent calls are group-committed: whoever takes the commit slot runs
// every queued fn in one transaction, so N writers that arrive while an
// fsync is in flight share the next one instead of queueing for N (CS-197,
// docs/benchmarks.md). A lone caller commits at once, with no added delay.
// Fns in a group see each other's writes in order, exactly as if their
// transactions had run back to back. If the group fails (any fn errs or
// panics, or the commit fails), nothing in it is written and each fn is run
// again in its own transaction, so one caller's error never becomes
// another's. A panic is re-raised in the goroutine of the caller whose fn
// panicked.
func (d *DB) Update(fn Op) error {
	c := &call{fn: fn, done: make(chan result, 1)}
	d.qmu.Lock()
	d.queue = append(d.queue, c)
	d.qmu.Unlock()

	// A caller either gets its result from an earlier committer that drained
	// its call, or takes the commit slot and runs the queue itself. It never
	// waits for the slot once its own result is in, so a finished caller is
	// not held behind later groups' fsyncs.
	var r result
	select {
	case r = <-c.done:
	case d.commit <- struct{}{}:
		d.qmu.Lock()
		group := d.queue
		d.queue = nil
		d.qmu.Unlock()
		d.run(group)
		<-d.commit
		r = <-c.done
	}
	if r.panic != nil {
		panic(r.panic)
	}
	return r.err
}

func (d *DB) run(group []*call) {
	if len(group) > 1 {
		var p any
		err := d.bolt.Update(func(tx *bolt.Tx) error {
			for _, c := range group {
				var err error
				if p, err = safe(c.fn, tx); err != nil || p != nil {
					return errors.New("store: group member failed")
				}
			}
			return d.injected()
		})
		if err == nil && p == nil {
			for _, c := range group {
				c.done <- result{}
			}
			return
		}
	}
	for _, c := range group {
		var r result
		err := d.bolt.Update(func(tx *bolt.Tx) error {
			var err error
			r.panic, err = safe(c.fn, tx)
			if r.panic != nil {
				return errors.New("store: write panicked")
			}
			if err != nil {
				return err
			}
			return d.injected()
		})
		if r.panic == nil {
			r.err = err
		}
		c.done <- r
	}
}

func (d *DB) injected() error {
	if d.fault != nil {
		return d.fault()
	}
	return nil
}

// safe runs fn, turning a panic into a value so the group's other callers
// are never left waiting.
func safe(fn Op, tx *bolt.Tx) (p any, err error) {
	defer func() { p = recover() }()
	return nil, fn(tx)
}

// View runs fn in a read transaction.
func (d *DB) View(fn func(tx *bolt.Tx) error) error { return d.bolt.View(fn) }

// Bucket creates the named bucket if needed.
func (d *DB) Bucket(name []byte) error {
	return d.bolt.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(name)
		return err
	})
}

// Path is the file's location.
func (d *DB) Path() string { return d.bolt.Path() }

// Close closes the file (and removes it if temporary).
func (d *DB) Close() error {
	err := d.bolt.Close()
	if d.temp != "" {
		_ = os.RemoveAll(d.temp)
	}
	return err
}
