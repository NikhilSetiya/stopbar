package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

type rig struct {
	db   *store.DB
	log  *Log
	keys map[string]ed25519.PublicKey
	path string
}

func newRig(t *testing.T, every uint64, n int) *rig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, k, _ := ed25519.GenerateKey(nil)
	ring := decision.NewKeyRing(k)
	l, err := New(Config{DB: db, Signer: ring, CheckpointEvery: every})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := l.Append(context.Background(), model.AuditDecision, map[string]any{"n": i, "request_id": "r"}); err != nil {
			t.Fatal(err)
		}
	}
	return &rig{db: db, log: l, keys: ring.PublicKeys(), path: path}
}

func (r *rig) verify(t *testing.T) (Report, error) {
	t.Helper()
	return Verify(r.db, r.keys, 0, 0)
}

func TestChainAndCheckpointsVerify(t *testing.T) {
	r := newRig(t, 4, 10)
	rep, err := r.verify(t)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Records != 10 || rep.Checkpoints != 2 || rep.LastCheckpointSeq != 8 || rep.Uncovered != 2 {
		t.Fatalf("report %+v", rep)
	}
	if err := r.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if rep, err = r.verify(t); err != nil || rep.Uncovered != 0 || rep.Checkpoints != 3 {
		t.Fatalf("after final checkpoint: %+v %v", rep, err)
	}
	if rep, err = Verify(r.db, r.keys, 5, 8); err != nil || rep.Records != 4 {
		t.Fatalf("partial range: %+v %v", rep, err)
	}
}

// raw edits the stored bytes, as an attacker with the file would.
func (r *rig) raw(t *testing.T, fn func(b *bolt.Bucket)) {
	t.Helper()
	if err := r.db.Update(func(tx *bolt.Tx) error { fn(tx.Bucket(recordsBucket)); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingFailsVerify(t *testing.T) {
	for name, tt := range map[string]struct {
		tamper func(t *testing.T, r *rig)
		want   string
	}{
		"edit one byte": {func(t *testing.T, r *rig) {
			r.raw(t, func(b *bolt.Bucket) {
				v := append([]byte(nil), b.Get(seqKey(3))...)
				i := strings.Index(string(v), `"n":2`)
				v[i+4] = '9' // one byte of the body
				_ = b.Put(seqKey(3), v)
			})
		}, "record 3 content does not match its hash"},
		"delete one record": {func(t *testing.T, r *rig) {
			r.raw(t, func(b *bolt.Bucket) { _ = b.Delete(seqKey(5)) })
		}, "record 5 is missing"},
		"reorder two records": {func(t *testing.T, r *rig) {
			r.raw(t, func(b *bolt.Bucket) {
				a, c := append([]byte(nil), b.Get(seqKey(2))...), append([]byte(nil), b.Get(seqKey(3))...)
				_ = b.Put(seqKey(2), c)
				_ = b.Put(seqKey(3), a)
			})
		}, "claims seq"},
		"rewrite a record and re-hash it": {func(t *testing.T, r *rig) {
			// The attacker recomputes record 6's own hash: the next link breaks.
			r.raw(t, func(b *bolt.Bucket) {
				var rec model.AuditRecord
				_ = json.Unmarshal(b.Get(seqKey(6)), &rec)
				rec.Body = map[string]any{"n": 999, "request_id": "forged"}
				rec.Hash, _ = recordHash(rec)
				v, _ := json.Marshal(rec)
				_ = b.Put(seqKey(6), v)
			})
		}, "chain broken at record 7"},
		"truncate the tail": {func(t *testing.T, r *rig) {
			r.raw(t, func(b *bolt.Bucket) { _ = b.Delete(seqKey(10)); _ = b.Delete(seqKey(9)); _ = b.Delete(seqKey(8)) })
		}, "checkpoint 8 covers a record that is missing"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 4, 10)
			tt.tamper(t, r)
			if _, err := r.verify(t); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestForgedCheckpointsFailVerify(t *testing.T) {
	r := newRig(t, 4, 8)
	if err := r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(checkpointsBucket)
		var cp checkpoint
		_ = json.Unmarshal(b.Get(seqKey(4)), &cp)
		cp.Sig = b64.EncodeToString(make([]byte, 64))
		v, _ := json.Marshal(cp)
		return b.Put(seqKey(4), v)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.verify(t); err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("forged checkpoint: %v", err)
	}
	r2 := newRig(t, 4, 8)
	if _, err := Verify(r2.db, map[string]ed25519.PublicKey{}, 0, 0); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unpinned key: %v", err)
	}
}

// A record and the state change it describes commit together or not at all.
func TestAppendTxIsAtomicWithState(t *testing.T) {
	r := newRig(t, 1000, 2)
	state := []byte("some_state")
	if err := r.db.Bucket(state); err != nil {
		t.Fatal(err)
	}
	err := r.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(state).Put([]byte("k"), []byte("v")); err != nil {
			return err
		}
		if err := r.log.AppendTx(tx, model.AuditEntry{Type: model.AuditCommit, Body: map[string]any{"x": 1}}); err != nil {
			return err
		}
		return errors.New("later step fails")
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	recs, _ := Records(r.db, 1, 0)
	var got []byte
	_ = r.db.View(func(tx *bolt.Tx) error { got = tx.Bucket(state).Get([]byte("k")); return nil })
	if len(recs) != 2 || got != nil {
		t.Fatalf("partial commit: %d records, state %q", len(recs), got)
	}
}

func TestReadOnlyOpenForOfflineVerify(t *testing.T) {
	r := newRig(t, 2, 4)
	_ = r.db.Close()
	ro, err := store.OpenReadOnly(r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if rep, err := Verify(ro, r.keys, 0, 0); err != nil || rep.Records != 4 || rep.Uncovered != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}
