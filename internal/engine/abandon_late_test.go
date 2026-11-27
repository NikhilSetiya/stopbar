package engine

import (
	"context"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// TestAbandonUndoesALateLanding (CS-197): when an evaluation's state lands
// after the gateway answered FAIL_CLOSED_STORE, Abandon voids its
// reservation (released even if committed, audited) and resolves a still
// pending escalation as a FAIL_CLOSED_STORE deny, so no approver can act on
// it. A resolved escalation is left alone.
func TestAbandonUndoesALateLanding(t *testing.T) {
	if CodeStore != gateway.CodeStore {
		t.Fatalf("engine %q and gateway %q disagree on the store code", CodeStore, gateway.CodeStore)
	}
	r := newRig()
	p := newFakePending()
	p.audit = r.audit
	r.cfg.Pending = p
	e := r.engine(t)
	p.m["esc"] = PendingEscalation{Request: model.ActionRequest{ID: "esc", Tenant: "test"}, State: model.EscalationPending}
	p.m["done"] = PendingEscalation{Request: model.ActionRequest{ID: "done", Tenant: "test"}, State: model.EscalationAllowed}

	e.Abandon(context.Background(), "esc")
	e.Abandon(context.Background(), "done")

	if len(r.limiter.voided) != 2 {
		t.Fatalf("voided %v, want both ids voided", r.limiter.voided)
	}
	if pe := p.m["esc"]; pe.State != model.EscalationDenied || pe.Decision == nil || !hasCode(*pe.Decision, CodeStore) {
		t.Fatalf("pending escalation after Abandon: %+v", pe)
	}
	if pe := p.m["done"]; pe.State != model.EscalationAllowed {
		t.Fatalf("a resolved escalation was changed: %+v", pe)
	}
}
