package audit

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// BenchmarkAppend is one audit record in its own durable (fsynced) bbolt
// transaction on a real file: what a deny or escalate record costs, and the
// floor under every other state write (CS-197, docs/benchmarks.md).
func BenchmarkAppend(b *testing.B) {
	db, err := store.Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	_, k, _ := ed25519.GenerateKey(nil)
	l, err := New(Config{DB: db, Signer: decision.NewKeyRing(k)})
	if err != nil {
		b.Fatal(err)
	}
	body := map[string]any{"decision": map[string]any{"request_id": "req_bench", "outcome": "deny",
		"reasons": []map[string]string{{"code": "POLICY_DENY", "policy_id": "delegatecall"}}}}
	b.ReportAllocs()
	for b.Loop() {
		if err := l.Append(context.Background(), model.AuditDecision, body); err != nil {
			b.Fatal(err)
		}
	}
}
