// Package audit is the hash-chained, append-only decision log (CS-171/172,
// LLD §11, spec/audit-hash-v1.md).
//
// Records live in the shared state file (internal/store). AppendTx joins the
// caller's transaction, so a record and the state change it describes (a
// reservation, a commit, a consumed nonce) are durable together or not at
// all. Every N records, and on Checkpoint, the head hash is signed with the
// decision key. Verify recomputes the whole chain and checks the signed
// checkpoints offline, from the file and the published keys alone.
package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

var (
	recordsBucket     = []byte("audit_records_v1")
	checkpointsBucket = []byte("audit_checkpoints_v1")
	b64               = base64.RawURLEncoding
)

// CheckpointDomain prefixes every checkpoint signature, so a checkpoint
// signature can never be mistaken for a decision token (or vice versa).
const CheckpointDomain = "stopbar-audit-checkpoint-v1\n"

// ErrUnavailable wraps any failure to append: the caller must fail closed.
var ErrUnavailable = errors.New("audit: log unavailable")

// CheckpointSigner signs checkpoint payloads (decision.KeyRing implements it).
type CheckpointSigner interface {
	SignCheckpoint(msg []byte) (kid string, sig []byte)
}

// Log appends records to the shared state file.
type Log struct {
	db     *store.DB
	signer CheckpointSigner
	every  uint64
	clock  func() time.Time
	mu     sync.Mutex // serialises Append's own transactions with Checkpoint
}

// Config wires a Log.
type Config struct {
	DB              *store.DB
	Signer          CheckpointSigner // nil: no checkpoints (tests only)
	CheckpointEvery uint64           // default 1000 (LLD §11)
	Clock           func() time.Time
}

// New opens the log's buckets.
func New(cfg Config) (*Log, error) {
	if cfg.DB == nil {
		return nil, errors.New("audit: no state file")
	}
	for _, b := range [][]byte{recordsBucket, checkpointsBucket} {
		if err := cfg.DB.Bucket(b); err != nil {
			return nil, err
		}
	}
	l := &Log{db: cfg.DB, signer: cfg.Signer, every: cfg.CheckpointEvery, clock: cfg.Clock}
	if l.every == 0 {
		l.every = 1000
	}
	if l.clock == nil {
		l.clock = time.Now
	}
	return l, nil
}

func seqKey(seq uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, seq)
	return k
}

// head returns the last record's seq and hash (GenesisHash when empty).
func head(tx *bolt.Tx) (uint64, string, error) {
	k, v := tx.Bucket(recordsBucket).Cursor().Last()
	if k == nil {
		return 0, canon.GenesisHash, nil
	}
	var r model.AuditRecord
	if err := json.Unmarshal(v, &r); err != nil {
		return 0, "", fmt.Errorf("audit: corrupt head record: %w", err)
	}
	return r.Seq, r.Hash, nil
}

// AppendTx appends a record inside tx. Use it from a state store's
// transaction; failures abort that transaction.
func (l *Log) AppendTx(tx *bolt.Tx, e model.AuditEntry) error {
	seq, prev, err := head(tx)
	if err != nil {
		return err
	}
	// Round-trip the body through JSON so the hash covers exactly the bytes
	// that are stored and later verified.
	raw, err := json.Marshal(e.Body)
	if err != nil {
		return err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	r := model.AuditRecord{Seq: seq + 1, TS: l.clock().UTC().Format(time.RFC3339Nano), Type: e.Type, Body: generic, PrevHash: prev}
	if r.Hash, err = canon.RecordHash(r.Seq, r.TS, string(r.Type), r.Body, r.PrevHash); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := tx.Bucket(recordsBucket).Put(seqKey(r.Seq), b); err != nil {
		return err
	}
	if l.signer != nil && r.Seq%l.every == 0 {
		return l.checkpointTx(tx, r.Seq, r.Hash)
	}
	return nil
}

// Op returns AppendTx as a store.Op.
func (l *Log) Op(e model.AuditEntry) store.Op {
	return func(tx *bolt.Tx) error { return l.AppendTx(tx, e) }
}

// Append writes a record in its own transaction (engine.AuditLog). Records
// with no state change of their own (deny, escalate) come through here.
func (l *Log) Append(_ context.Context, typ model.AuditRecordType, body any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.db.Update(l.Op(model.AuditEntry{Type: typ, Body: body})); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Checkpoint signs the current head (e.g. at shutdown), so nothing appended
// before it can be truncated without verify noticing.
func (l *Log) Checkpoint() error {
	if l.signer == nil {
		return errors.New("audit: no checkpoint signer")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.db.Update(func(tx *bolt.Tx) error {
		seq, h, err := head(tx)
		if err != nil || seq == 0 {
			return err
		}
		if tx.Bucket(checkpointsBucket).Get(seqKey(seq)) != nil {
			return nil // already covered
		}
		return l.checkpointTx(tx, seq, h)
	})
}

// checkpoint is the stored form: payload is the JCS bytes that were signed.
type checkpoint struct {
	Payload string `json:"payload"` // JCS {"hash","seq","ts","v"}
	Kid     string `json:"kid"`
	Sig     string `json:"sig"` // base64url Ed25519 over CheckpointDomain + payload
}

type checkpointPayload struct {
	V    int    `json:"v"`
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	TS   string `json:"ts"`
}

func (l *Log) checkpointTx(tx *bolt.Tx, seq uint64, hash string) error {
	p, err := canon.Marshal(checkpointPayload{V: 1, Seq: seq, Hash: hash, TS: l.clock().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	kid, sig := l.signer.SignCheckpoint(append([]byte(CheckpointDomain), p...))
	b, err := json.Marshal(checkpoint{Payload: string(p), Kid: kid, Sig: b64.EncodeToString(sig)})
	if err != nil {
		return err
	}
	return tx.Bucket(checkpointsBucket).Put(seqKey(seq), b)
}

// ---- reading and verification (offline) ----

// Records returns records with from ≤ seq ≤ to (to 0: through the end), as
// stored, without verifying them.
func Records(db *store.DB, from, to uint64) ([]model.AuditRecord, error) {
	var out []model.AuditRecord
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(recordsBucket)
		if b == nil {
			return errors.New("audit: no audit log in this state file")
		}
		c := b.Cursor()
		for k, v := c.Seek(seqKey(from)); k != nil; k, v = c.Next() {
			if to != 0 && binary.BigEndian.Uint64(k) > to {
				break
			}
			var r model.AuditRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("audit: record at key %d is not valid JSON", binary.BigEndian.Uint64(k))
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

// Report summarises a verification.
type Report struct {
	From, To          uint64
	Records           int
	Checkpoints       int
	LastCheckpointSeq uint64
	Uncovered         uint64 // records after the last verified checkpoint
	Head              string
}

// Verify recomputes every record hash and link in [from, to] (to 0: through
// the end) and checks every checkpoint in the file against the recomputed
// chain and the given public keys. It needs nothing but the file and the
// published keys. Starting above 1 trusts the stored hash of record from-1.
func Verify(db *store.DB, keys map[string]ed25519.PublicKey, from, to uint64) (Report, error) {
	if from == 0 {
		from = 1
	}
	rep := Report{From: from}
	hashes := map[uint64]string{}
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(recordsBucket)
		if b == nil {
			return errors.New("audit: no audit log in this state file")
		}
		prev := canon.GenesisHash
		if from > 1 {
			v := b.Get(seqKey(from - 1))
			if v == nil {
				return fmt.Errorf("audit: record %d (the anchor for --from %d) is missing", from-1, from)
			}
			var r model.AuditRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("audit: record %d is not valid JSON", from-1)
			}
			prev = r.Hash
		}
		want := from
		c := b.Cursor()
		for k, v := c.Seek(seqKey(from)); k != nil; k, v = c.Next() {
			key := binary.BigEndian.Uint64(k)
			if to != 0 && key > to {
				break
			}
			if key != want {
				return fmt.Errorf("audit: record %d is missing (next stored is %d)", want, key)
			}
			var r model.AuditRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("audit: record %d is not valid JSON (edited?)", key)
			}
			if r.Seq != key {
				return fmt.Errorf("audit: record stored at %d claims seq %d (reordered?)", key, r.Seq)
			}
			if r.PrevHash != prev {
				return fmt.Errorf("audit: chain broken at record %d: prev_hash does not match record %d", key, key-1)
			}
			h, err := canon.RecordHash(r.Seq, r.TS, string(r.Type), r.Body, r.PrevHash)
			if err != nil {
				return fmt.Errorf("audit: record %d: %w", key, err)
			}
			if h != r.Hash {
				return fmt.Errorf("audit: record %d content does not match its hash (edited?)", key)
			}
			hashes[key] = h
			prev = h
			rep.To, rep.Head = key, h
			rep.Records++
			want++
		}
		if to != 0 && rep.To != to {
			return fmt.Errorf("audit: range ends at %d, wanted through %d (records missing at the end)", rep.To, to)
		}

		cb := tx.Bucket(checkpointsBucket)
		if cb == nil {
			return nil
		}
		return cb.ForEach(func(k, v []byte) error {
			seq := binary.BigEndian.Uint64(k)
			var cp checkpoint
			var p checkpointPayload
			if err := json.Unmarshal(v, &cp); err != nil || json.Unmarshal([]byte(cp.Payload), &p) != nil || p.Seq != seq || p.V != 1 {
				return fmt.Errorf("audit: checkpoint %d is malformed", seq)
			}
			pub, ok := keys[cp.Kid]
			if !ok {
				return fmt.Errorf("audit: checkpoint %d signed by unknown key %s", seq, cp.Kid)
			}
			sig, err := b64.DecodeString(cp.Sig)
			if err != nil || !ed25519.Verify(pub, append([]byte(CheckpointDomain), cp.Payload...), sig) {
				return fmt.Errorf("audit: checkpoint %d has a bad signature", seq)
			}
			if seq < from || (to != 0 && seq > to) {
				return nil // outside the verified range
			}
			h, ok := hashes[seq]
			if !ok {
				return fmt.Errorf("audit: checkpoint %d covers a record that is missing (truncated?)", seq)
			}
			if h != p.Hash {
				return fmt.Errorf("audit: checkpoint %d does not match the chain", seq)
			}
			rep.Checkpoints++
			if seq > rep.LastCheckpointSeq {
				rep.LastCheckpointSeq = seq
			}
			return nil
		})
	})
	if err == nil && rep.To > rep.LastCheckpointSeq {
		rep.Uncovered = rep.To - rep.LastCheckpointSeq
	}
	return rep, err
}

func recordHash(r model.AuditRecord) (string, error) {
	return canon.RecordHash(r.Seq, r.TS, string(r.Type), r.Body, r.PrevHash)
}
