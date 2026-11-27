package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// TestResolvedEscalationsAreCompactedAfterRetention (CS-197): a resolved
// escalation (allowed, denied, expired) is kept for the retention and then
// compacted by a later write; a pending one is never compacted, however old;
// the audit log keeps every record; retention 0 keeps everything.
func TestResolvedEscalationsAreCompactedAfterRetention(t *testing.T) {
	for _, retention := range []time.Duration{time.Hour, 0} {
		db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		lg, err := audit.New(audit.Config{DB: db})
		if err != nil {
			t.Fatal(err)
		}
		p, err := newPendingStore(db, lg, retention)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
		p.clock = func() time.Time { return now }
		ctx := context.Background()
		rec := func(id string) *model.AuditEntry {
			return &model.AuditEntry{Type: model.AuditDecision, Body: map[string]any{"request_id": id}}
		}
		put := func(id string, state model.EscalationState, resolved *time.Time) {
			t.Helper()
			e := engine.PendingEscalation{Request: model.ActionRequest{ID: id, Tenant: "t"}, IssuedAt: now.Add(-48 * time.Hour), State: state, ResolvedAt: resolved}
			if err := p.Put(ctx, e, rec(id)); err != nil {
				t.Fatal(err)
			}
		}
		old := now.Add(-2 * time.Hour)
		put("pending-old", model.EscalationPending, nil)
		for _, s := range []model.EscalationState{model.EscalationAllowed, model.EscalationDenied, model.EscalationExpired} {
			put(string(s)+"-old", s, &old)
		}
		recent := now.Add(-time.Minute)
		put("denied-recent", model.EscalationDenied, &recent)
		put("trigger", model.EscalationPending, nil) // the next write compacts

		want := map[string]bool{"pending-old": true, "denied-recent": true, "trigger": true,
			"allowed-old": retention == 0, "denied-old": retention == 0, "expired-old": retention == 0}
		for id, keep := range want {
			if _, ok, err := p.Get(ctx, id); err != nil || ok != keep {
				t.Errorf("retention %s: %s present=%v (err %v), want %v", retention, id, ok, err, keep)
			}
		}
		if recs, _ := audit.Records(db, 0, 0); len(recs) != 6 {
			t.Errorf("retention %s: %d audit records, want 6 (the log is never compacted)", retention, len(recs))
		}
		_ = db.Close()
	}
}
