package enrich

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

const (
	payee    = "0x7a25a1c4e3b2d1f09876543210fedcba98760c21"
	poisoned = "0x7a25ffffffffffffffffffffffffffffffff0c21" // same first and last 4 hex digits
	self     = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
)

func newRegistry(t *testing.T) (*Registry, *store.DB) {
	t.Helper()
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenRegistry(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	return r, db
}

func TestSimilar(t *testing.T) {
	for _, tt := range []struct {
		name string
		b    string
		want bool
	}{
		{"same address is not similar (it is known)", payee, false},
		{"first 4 and last 4 match", poisoned, true},
		{"first 8 match", "0x7a25a1c4000000000000000000000000000000ff", true},
		{"last 8 match", "0xff00000000000000000000000000000098760c21", true},
		{"first 4, last 3", "0x7a25ffffffffffffffffffffffffffffffff1c21", false},
		{"first 3, last 4", "0x7a2fffffffffffffffffffffffffffffffff0c21", false},
		{"first 7 only", "0x7a25a1cfffffffffffffffffffffffffffffffff", false},
		{"unrelated", "0x9999999999999999999999999999999999999999", false},
		{"not an address", "0x7a25", false},
	} {
		if got := Similar(payee, tt.b); got != tt.want {
			t.Errorf("%s: Similar(%s, %s) = %v, want %v", tt.name, payee, tt.b, got, tt.want)
		}
	}
}

// Changes are idempotent, normalised, scoped per tenant, and each real
// change is one audit record in the same transaction.
func TestRegistryAddRemoveListAudited(t *testing.T) {
	r, db := newRegistry(t)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	if added, err := r.Add("acme", "0x7A25A1C4E3B2D1F09876543210FEDCBA98760C21", "payroll", "cli", now); err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	if added, err := r.Add("acme", payee, "", "cli", now); err != nil || added {
		t.Fatalf("second add must be a no-op: %v %v", added, err)
	}
	if _, err := r.Add("acme", "0x1234", "", "cli", now); err == nil {
		t.Fatal("malformed address accepted")
	}
	if _, err := r.Add("", payee, "", "cli", now); err == nil {
		t.Fatal("empty tenant accepted")
	}
	cs, err := r.List("acme")
	if err != nil || len(cs) != 1 || cs[0].Address != payee || cs[0].Label != "payroll" || cs[0].Source != "cli" || !cs[0].AddedAt.Equal(now) {
		t.Fatalf("list: %+v %v", cs, err)
	}
	if cs, _ := r.List("other"); len(cs) != 0 {
		t.Fatalf("tenant isolation: other sees %+v", cs)
	}
	if removed, err := r.Remove("acme", payee, "cli", now); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if removed, err := r.Remove("acme", payee, "cli", now); err != nil || removed {
		t.Fatalf("second remove must be a no-op: %v %v", removed, err)
	}
	recs, err := audit.Records(db, 1, 0)
	if err != nil || len(recs) != 2 {
		t.Fatalf("want 2 audit records (add, remove), got %d %v", len(recs), err)
	}
	for i, op := range []string{"add", "remove"} {
		b := recs[i].Body.(map[string]any)
		if recs[i].Type != model.AuditDestination || b["op"] != op || b["address"] != payee || b["tenant"] != "acme" {
			t.Fatalf("record %d: %+v", i, recs[i])
		}
	}
	if _, err := audit.Verify(db, nil, 1, 0); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	ro, _ := OpenRegistry(db, nil)
	if _, err := ro.Add("acme", payee, "", "cli", now); err == nil {
		t.Fatal("a registry with no audit log must refuse changes")
	}
}

func TestRegistryEnrich(t *testing.T) {
	r, _ := newRegistry(t)
	if _, err := r.Add("acme", payee, "", "cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, tenant, dest string
		kind               model.ActionKind
		known, similar     bool
		flags              []string
	}{
		{"registered", "acme", payee, model.KindEVMTx, true, false, []string{}},
		{"registered, mixed case", "acme", "0x7A25A1C4E3B2D1F09876543210FEDCBA98760C21", model.KindEVMTx, true, false, []string{}},
		{"poisoned lookalike", "acme", poisoned, model.KindEVMTx, false, true, []string{FlagNewDestination, FlagSimilarDestination}},
		{"new", "acme", "0x9999999999999999999999999999999999999999", model.KindEVMTx, false, false, []string{FlagNewDestination}},
		{"the sending wallet itself", "acme", self, model.KindEVMTx, true, false, []string{}},
		{"another tenant's registry does not count", "other", payee, model.KindEVMTx, false, false, []string{FlagNewDestination}},
		{"no destination", "acme", "", model.KindEVMTx, false, false, []string{}},
		{"tool call", "acme", payee, model.KindToolCall, false, false, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			er := &model.EnrichedRequest{
				Request: model.ActionRequest{Tenant: tt.tenant, Action: model.Action{Kind: tt.kind, From: self}},
				Intent:  model.IntentSummary{Destination: tt.dest, Flags: []string{}},
			}
			if err := r.Enrich(context.Background(), er); err != nil {
				t.Fatal(err)
			}
			if er.Destination.Known != tt.known || er.Destination.SimilarToKnown != tt.similar || !slices.Equal(er.Intent.Flags, tt.flags) {
				t.Fatalf("got %+v flags %v, want known=%v similar=%v flags %v", er.Destination, er.Intent.Flags, tt.known, tt.similar, tt.flags)
			}
		})
	}
	// Enrich never writes into a flag slice it shares with the decoder's intent.
	shared := make([]string, 1, 4)
	shared[0] = "x"
	er := &model.EnrichedRequest{Request: model.ActionRequest{Tenant: "acme", Action: model.Action{Kind: model.KindEVMTx, From: self}},
		Intent: model.IntentSummary{Destination: poisoned, Flags: shared}}
	if err := r.Enrich(context.Background(), er); err != nil {
		t.Fatal(err)
	}
	if shared[:2][1] != "" {
		t.Fatalf("enrich wrote %q into the shared backing array", shared[:2][1])
	}
}
