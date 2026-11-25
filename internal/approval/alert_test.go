package approval

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

func TestResolutionCarriesVetoVote(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	v := Vote{Kid: "key-bob", Owner: Owner{AgentID: "bob-agent"}, Decision: Reject, Expiry: now.Add(time.Hour)}
	res, err := tally.Add(v, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Rejected {
		t.Fatalf("Outcome = %v, want Rejected", res.Outcome)
	}
	if res.Veto == nil {
		t.Fatal("Veto is nil, want the rejecting vote")
	}
	if res.Veto.Kid != "key-bob" || res.Veto.Owner.AgentID != "bob-agent" {
		t.Fatalf("Veto = %+v, want the exact rejecting vote", res.Veto)
	}
}

func TestResolutionVetoNilWhenNotRejected(t *testing.T) {
	tally := newTally(2)
	now := time.Now()
	res, _ := tally.Add(vote("k1", Approve, now.Add(time.Hour)), now)
	if res.Veto != nil {
		t.Fatalf("Veto = %+v, want nil while Pending", res.Veto)
	}
}

func TestAlertsVetoCounterByTenantAndKind(t *testing.T) {
	var buf bytes.Buffer
	a := NewAlerts(slog.New(slog.NewTextHandler(&buf, nil)))
	v := Vote{Kid: "key-bob", Owner: Owner{AgentID: "bob-agent"}, Decision: Reject}

	a.Veto("acme", VetoKindEscalation, v)
	a.Veto("acme", VetoKindEscalation, v)
	a.Veto("other-tenant", VetoKindBreakerReset, v)

	counts := a.Counters()
	if counts[[2]string{"acme", VetoKindEscalation}] != 2 {
		t.Fatalf("acme/escalation count = %d, want 2", counts[[2]string{"acme", VetoKindEscalation}])
	}
	if counts[[2]string{"other-tenant", VetoKindBreakerReset}] != 1 {
		t.Fatalf("other-tenant/breaker_reset count = %d, want 1", counts[[2]string{"other-tenant", VetoKindBreakerReset}])
	}
	if counts[[2]string{"acme", VetoKindBreakerReset}] != 0 {
		t.Fatalf("acme/breaker_reset count = %d, want 0 (no such veto recorded)", counts[[2]string{"acme", VetoKindBreakerReset}])
	}
}

func TestAlertsVetoLogsHighSeverity(t *testing.T) {
	var buf bytes.Buffer
	a := NewAlerts(slog.New(slog.NewTextHandler(&buf, nil)))
	v := Vote{Kid: "key-bob", Owner: Owner{AgentID: "bob-agent", KeyID: "ak_bob"}, Decision: Reject}
	a.Veto("acme", VetoKindEscalation, v)

	out := buf.String()
	for _, want := range []string{"severity=high", "stopbar_approval_rejects_total", "tenant=acme", "kind=escalation", "kid=key-bob", "owner_agent_id=bob-agent", "owner_key_id=ak_bob"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log line %q missing %q", out, want)
		}
	}
}

func TestAlertsCountersSnapshotIsIndependent(t *testing.T) {
	a := NewAlerts(nil)
	v := Vote{Kid: "k", Owner: Owner{KeyID: "ak_x"}, Decision: Reject}
	a.Veto("acme", VetoKindEscalation, v)
	snap := a.Counters()
	snap[[2]string{"acme", VetoKindEscalation}] = 999 // mutate the snapshot
	if got := a.Counters()[[2]string{"acme", VetoKindEscalation}]; got != 1 {
		t.Fatalf("internal count = %d, want 1 (mutating a snapshot must not affect it)", got)
	}
}

func TestVetoAuditEntryCarriesRejectingOwner(t *testing.T) {
	v := Vote{Kid: "key-bob", Owner: Owner{AgentID: "bob-agent", KeyID: "ak_bob"}, Decision: Reject}
	e := VetoAuditEntry("acme", VetoKindEscalation, v)
	if e.Type != model.AuditApproval {
		t.Fatalf("Type = %v, want model.AuditApproval", e.Type)
	}
	body, ok := e.Body.(map[string]any)
	if !ok {
		t.Fatalf("Body = %T, want map[string]any", e.Body)
	}
	if body["tenant"] != "acme" || body["kind"] != VetoKindEscalation || body["kid"] != "key-bob" {
		t.Fatalf("body = %+v, missing tenant/kind/kid", body)
	}
	owner, ok := body["owner"].(Owner)
	if !ok || owner.AgentID != "bob-agent" || owner.KeyID != "ak_bob" {
		t.Fatalf("body[owner] = %+v, want the rejecting vote's Owner", body["owner"])
	}
}
