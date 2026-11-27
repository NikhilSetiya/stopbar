package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// TestAppendInUnitRecordsTheBodyAsAppended (review finding 4 on #146): a
// record queued in a store.Unit is the body as it was at Append, not at unit
// commit, even if the caller changes it in between.
func TestAppendInUnitRecordsTheBodyAsAppended(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	l, err := New(Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	u := db.NewUnit()
	body := map[string]any{"request_id": "r", "args": map[string]any{"limit": "50000"}}
	if err := l.Append(store.WithUnit(context.Background(), u), model.AuditDecision, body); err != nil {
		t.Fatal(err)
	}
	body["args"].(map[string]any)["limit"] = "1" // after Append, before commit
	body["late"] = true
	if err := u.Commit(); err != nil {
		t.Fatal(err)
	}
	recs, err := Records(db, 0, 0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	b := recs[0].Body.(map[string]any)
	if b["args"].(map[string]any)["limit"] != "50000" || b["late"] != nil {
		t.Fatalf("recorded body %v, want it as appended", b)
	}
}
