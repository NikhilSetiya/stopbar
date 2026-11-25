package approval

import (
	"log/slog"
	"sync"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Veto kinds label the "kind" dimension of stopbar_approval_rejects_total
// and the veto audit record (spec §9/§12): which flow a single-approver
// veto happened in. A breaker reset object's decision is always
// ResetDecision (spec §3) — VerifyBreakerReset never accepts anything
// else — so VetoKindBreakerReset exists for the generic mechanism and any
// future reset-reject path; today only escalations ever veto.
const (
	VetoKindEscalation   = "escalation"
	VetoKindBreakerReset = "breaker_reset"
)

// Alerts is the side-effecting sink for approval-reject vetoes: a
// stopbar_approval_rejects_total counter by (tenant, kind) for /metrics,
// and a high-severity structured log line naming the rejecting owner.
// Tally itself stays pure (Add never logs or counts anything; it returns
// the veto in Resolution.Veto). One Alerts is meant to be constructed once
// and shared for the deployment's lifetime; Veto is called every time a
// Tally resolves Rejected.
type Alerts struct {
	mu     sync.Mutex
	counts map[[2]string]uint64 // {tenant, kind}
	log    *slog.Logger
}

// NewAlerts returns a sink that logs to log (slog.Default() if nil).
func NewAlerts(log *slog.Logger) *Alerts {
	if log == nil {
		log = slog.Default()
	}
	return &Alerts{counts: map[[2]string]uint64{}, log: log}
}

// Veto records one reject veto for tenant/kind (VetoKindEscalation or
// VetoKindBreakerReset): a high-severity structured log line, and the
// stopbar_approval_rejects_total counter. v is the exact vote that caused
// the veto, as returned in Resolution.Veto — it is never a vote Tally
// merely held without resolving.
func (a *Alerts) Veto(tenant, kind string, v Vote) {
	a.mu.Lock()
	a.counts[[2]string{tenant, kind}]++
	a.mu.Unlock()
	a.log.Error("approval vetoed: a single valid reject denies regardless of quorum (spec §9)",
		"severity", "high", "alert", "approval_reject", "metric", "stopbar_approval_rejects_total",
		"tenant", tenant, "kind", kind, "kid", v.Kid, "owner_agent_id", v.Owner.AgentID, "owner_key_id", v.Owner.KeyID)
}

// Counters reports stopbar_approval_rejects_total by (tenant, kind), for
// /metrics. The map is a snapshot; it is never mutated by the caller.
func (a *Alerts) Counters() map[[2]string]uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[[2]string]uint64, len(a.counts))
	for k, n := range a.counts {
		out[k] = n
	}
	return out
}

// VetoAuditEntry is the audit record for a reject veto (spec §9, LLD §12),
// ready to write in the same bbolt transaction as the state change it
// resolves — the pending escalation's deletion, or the breaker status —
// per CLAUDE.md's rule that every audit record is written in the same
// transaction as the state change it describes. tenant and kind label it
// the same way the /metrics counter is labeled; v is the exact vote that
// caused the veto (Resolution.Veto), so the record names the rejecting
// owner, never only a kid.
func VetoAuditEntry(tenant, kind string, v Vote) *model.AuditEntry {
	return &model.AuditEntry{Type: model.AuditApproval, Body: map[string]any{
		"event": "veto", "tenant": tenant, "kind": kind,
		"kid": v.Kid, "owner": v.Owner, "decision": v.Decision,
	}}
}
