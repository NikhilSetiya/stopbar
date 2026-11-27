// Package store is Stopbar's durable state: one bbolt file holding the
// limiter, nonce, spent-token and audit buckets. Sharing one file is what
// lets an audit record be written in the same transaction as the state
// change it describes (LLD §11): either both are durable or neither is.
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	commit chan struct{}         // the commit slot (capacity 1): held while a group commits
	fault  func() error          // tests only: fails each transaction as a failed commit would
	broken atomic.Pointer[error] // set by the first failed commit: every later write fails (see ErrBroken)
}

// ErrBroken is returned by every write after a commit (or its fsync) failed.
// Such a failure is ambiguous: the transaction may or may not be on disk. A
// retry could append the same audit record twice, and a rollback could undo
// in memory what is in fact durable. So the store stops taking writes, every
// caller fails closed, and the state file must be re-opened (restart
// stopbard), which reads back what is really there.
var ErrBroken = errors.New("store: a commit failed; the state file must be re-opened (restart stopbard)")

// Err reports whether the store is broken (ErrBroken, wrapping the commit
// error), or nil.
func (d *DB) Err() error {
	if e := d.broken.Load(); e != nil {
		return fmt.Errorf("%w: %w", ErrBroken, *e)
	}
	return nil
}

func (d *DB) breakOn(err error) error {
	d.broken.CompareAndSwap(nil, &err)
	return d.Err()
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
// panicked. A failed commit is different: it breaks the store (ErrBroken),
// fails every caller in the group, and is never retried.
func (d *DB) Update(fn Op) error {
	if err := d.Err(); err != nil {
		return err
	}
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
	if err := d.Err(); err != nil {
		for _, c := range group {
			c.done <- result{err: err}
		}
		return
	}
	if len(group) > 1 {
		var p any
		member := false // a member erred or panicked (retry alone), as opposed to the commit failing
		err := d.bolt.Update(func(tx *bolt.Tx) error {
			for _, c := range group {
				var err error
				if p, err = safe(c.fn, tx); err != nil || p != nil {
					member = true
					return errors.New("store: group member failed")
				}
			}
			return d.injected()
		})
		switch {
		case err == nil:
			for _, c := range group {
				c.done <- result{}
			}
			return
		case !member:
			broken := d.breakOn(err)
			for _, c := range group {
				c.done <- result{err: broken}
			}
			return
		}
	}
	for _, c := range group {
		var r result
		member := false
		err := d.bolt.Update(func(tx *bolt.Tx) error {
			if err := d.Err(); err != nil { // an earlier member's commit broke the store
				member = true
				return err
			}
			var err error
			r.panic, err = safe(c.fn, tx)
			if r.panic != nil {
				member = true
				return errors.New("store: write panicked")
			}
			if err != nil {
				member = true
				return err
			}
			return d.injected()
		})
		switch {
		case r.panic != nil:
		case err != nil && !member:
			r.err = d.breakOn(err)
		default:
			r.err = err
		}
		c.done <- r
	}
}

// SetFaultForTest makes every write transaction call f after its writes and
// just before bbolt commits it: an error fails the transaction as a failed
// commit would, and blocking in f stalls it as a stuck fsync would. Tests
// only; set it before any concurrent writes.
func (d *DB) SetFaultForTest(f func() error) { d.fault = f }

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

// Unit collects the writes of one evaluation so they commit in ONE
// transaction with one fsync (CS-197, ADR 0009): the consumed nonce and its
// request record, the reservation and its decision record, the spent token,
// the commit record. Each write still carries its own audit record, so every
// record stays in the same transaction as the state change it describes.
//
// Nothing a unit holds is acknowledged until Commit returns nil: the caller
// (the gateway) answers only after that, and answers fail-closed otherwise.
type Unit struct {
	db        *DB
	mu        sync.Mutex
	ops       []Op
	after     []func(error)
	done      bool
	abandoned atomic.Bool
}

// ErrAbandoned fails a unit whose caller stopped waiting for it (Abandon).
var ErrAbandoned = errors.New("store: unit abandoned by its caller (store timeout)")

// Abandon tells a unit its caller stopped waiting and has answered without
// it (CS-197, FAIL_CLOSED_STORE). If its transaction has not yet passed its
// last write, the transaction fails with ErrAbandoned: nothing of it lands
// and every after callback rolls back. If it was already committing (its
// fsync was in flight), it still lands, and Commit returns nil; the caller
// must then undo what landed (engine.Abandon).
func (u *Unit) Abandon() { u.abandoned.Store(true) }

type unitKey struct{}

// NewUnit starts a unit on d. Bind it to a context with WithUnit.
func (d *DB) NewUnit() *Unit { return &Unit{db: d} }

// WithUnit returns ctx carrying u: Write calls under it join u.
func WithUnit(ctx context.Context, u *Unit) context.Context {
	return context.WithValue(ctx, unitKey{}, u)
}

// UnitFrom returns the unit ctx carries, or nil.
func UnitFrom(ctx context.Context) *Unit {
	u, _ := ctx.Value(unitKey{}).(*Unit)
	return u
}

// Write runs op durably. Under a context carrying an open unit on d, op joins
// the unit and Write returns nil at once; after(err) runs when the unit
// commits or fails. Otherwise op runs in its own transaction now (Update) and
// after(err) runs before Write returns its error. A write that arrives after
// its unit committed (a component that outlived its stage timeout) also runs
// on its own, so nothing is ever dropped. after may be nil.
func (d *DB) Write(ctx context.Context, op Op, after func(error)) error {
	if u := UnitFrom(ctx); u != nil && u.db == d {
		u.mu.Lock()
		if !u.done {
			u.ops = append(u.ops, op)
			if after != nil {
				u.after = append(u.after, after)
			}
			u.mu.Unlock()
			return nil
		}
		u.mu.Unlock()
	}
	if after == nil {
		return d.Update(op)
	}
	// after runs exactly once, even if op panics (then with an error, before
	// the panic is re-raised), so no component is left holding state.
	ran := false
	defer func() {
		if p := recover(); p != nil {
			if !ran {
				after(fmt.Errorf("store: write panicked: %v", p))
			}
			panic(p)
		}
	}()
	err := d.Update(op)
	ran = true
	after(err)
	return err
}

// Commit writes every queued op in one transaction (group-committed with
// other writers, Update), then runs the after callbacks, last first, with
// the result: on failure nothing in the unit is written and each component
// rolls back what it held in memory. It returns once the transaction is
// fsynced, or failed.
func (u *Unit) Commit() error {
	u.mu.Lock()
	u.done = true
	ops, after := u.ops, u.after
	u.ops, u.after = nil, nil // a second Commit is a no-op
	u.mu.Unlock()
	var err error
	// The callbacks run exactly once, last first, whatever happens: if an op
	// panics they get an error (and roll back) before the panic is re-raised,
	// so no nonce stays pending and no limiter entry stays settling.
	settled := false
	defer func() {
		if p := recover(); p != nil {
			if !settled {
				perr := fmt.Errorf("store: unit write panicked: %v", p)
				for i := len(after) - 1; i >= 0; i-- {
					after[i](perr)
				}
			}
			panic(p)
		}
	}()
	if len(ops) > 0 {
		err = u.db.Update(func(tx *bolt.Tx) error {
			for _, op := range ops {
				if err := op(tx); err != nil {
					return err
				}
			}
			if u.abandoned.Load() { // checked last: the latest point before bbolt commits
				return ErrAbandoned
			}
			return nil
		})
	}
	settled = true
	for i := len(after) - 1; i >= 0; i-- {
		after[i](err)
	}
	return err
}
