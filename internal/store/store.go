// Package store is Stopbar's durable state: one bbolt file holding the
// limiter, nonce, spent-token and audit buckets. Sharing one file is what
// lets an audit record be written in the same transaction as the state
// change it describes (LLD §11): either both are durable or neither is.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DB is the shared state file. bbolt serialises write transactions and takes
// an exclusive file lock, so two processes cannot share one state by accident.
type DB struct {
	bolt *bolt.DB
	temp string // set when the file lives in a temporary directory
}

// Op is a write that joins a caller's transaction (e.g. an audit append).
type Op func(tx *bolt.Tx) error

// Open opens or creates the state file at path.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return &DB{bolt: b}, nil
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
	return &DB{bolt: b}, nil
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

// Update runs fn in one write transaction.
func (d *DB) Update(fn Op) error { return d.bolt.Update(fn) }

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
