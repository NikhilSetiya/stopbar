// Package engine orchestrates one evaluation (LLD §2, §12):
//
//	normalize → decode → enrich → policy → limiter → sign → audit
//
// It always returns a decision, never an error: any component failure,
// timeout, panic or broken invariant becomes a deny whose reason carries a
// FAIL_CLOSED_<STAGE> code. Only the allow path reserves limiter capacity
// and signs a token, and an allow is returned only once it is audited.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Decoder renders an action into an independent intent summary.
type Decoder interface {
	Supports(a model.Action) bool
	Decode(ctx context.Context, a model.Action) (model.IntentSummary, error)
}

// Enricher adds policy context. It must mark staleness rather than guess
// (e.g. PriceStale), and may only add taint, never remove it.
type Enricher interface {
	Enrich(ctx context.Context, req *model.EnrichedRequest) error
}

// Policy evaluates the enriched request (CS-111/112: Cedar bundle + combiner).
type Policy interface {
	Evaluate(ctx context.Context, req model.EnrichedRequest) (PolicyResult, error)
}

// PolicyResult is the combined policy outcome.
type PolicyResult struct {
	Outcome    model.Outcome
	Reasons    []model.Reason // required for deny/escalate
	BundleHash string         // sha256:<hex> of the active bundle
}

// Limiter holds value/velocity capacity (CS-121/122). It derives its own keys
// and amounts from the enriched request. Reserving the same id twice must not
// double-count. The engine releases after any failed or timed-out Reserve in
// case a late reservation lands, and treats ErrUnknownReservation and
// ErrReservationExpired from that Release as "nothing held".
//
// Each call takes the audit record describing it, and the limiter writes
// both in one transaction (LLD §11). If the record cannot be written, the
// state change does not happen and the error wraps ErrAuditUnavailable.
type Limiter interface {
	Reserve(ctx context.Context, id string, req model.EnrichedRequest, ttl time.Duration, rec *model.AuditEntry) error
	Commit(ctx context.Context, id, txRef string, rec *model.AuditEntry) error
	Release(ctx context.Context, id string, rec *model.AuditEntry) error
	// Owner reports the tenant and agent a reservation was made for, so
	// commit/release over HTTP (CS-105) can be scoped to the requester.
	Owner(id string) (tenant, agent string, ok bool)
}

// Domain errors a Limiter returns; anything else is FAIL_CLOSED_LIMITER.
// Commit and Release return ErrUnknownReservation or ErrReservationExpired
// for an ID with nothing to act on, and ErrAlreadyCommitted for a release (or
// a commit with another tx_ref) of a committed one. Those three live in model
// so the gateway can map them without importing the engine.
var (
	ErrCapExceeded        = errors.New("limiter: cap exceeded")
	ErrCircuitOpen        = errors.New("limiter: circuit breaker open")
	ErrUnknownReservation = model.ErrUnknownReservation
	ErrReservationExpired = model.ErrReservationExpired
	ErrAlreadyCommitted   = model.ErrAlreadyCommitted
	// ErrAuditUnavailable: the audit record (and the state change it
	// describes) could not be written.
	ErrAuditUnavailable = errors.New("audit unavailable")
)

// Signer issues the decision token for an allow (CS-161, decision.Signer).
// It needs the request for the token's tenant and nonce claims.
type Signer interface {
	Sign(ctx context.Context, req model.ActionRequest, d model.Decision) (token string, err error)
}

// AuditLog appends to the hash chain (CS-171).
type AuditLog interface {
	Append(ctx context.Context, typ model.AuditRecordType, body any) error
}

// Reason codes (LLD §12).
const (
	CodePolicy          = "POLICY"
	CodeNormalize       = "FAIL_CLOSED_NORMALIZE"
	CodeDecoder         = "FAIL_CLOSED_DECODER"
	CodeEnrich          = "FAIL_CLOSED_ENRICH"
	CodePolicyFail      = "FAIL_CLOSED_POLICY"
	CodeLimiter         = "FAIL_CLOSED_LIMITER"
	CodeSigner          = "FAIL_CLOSED_SIGNER"
	CodeAudit           = "FAIL_CLOSED_AUDIT"
	CodeEngine          = "FAIL_CLOSED_ENGINE"
	CodeCapExceeded     = "CAP_EXCEEDED"
	CodeCircuitOpen     = "CIRCUIT_OPEN"
	CodeApprovalExpired = "APPROVAL_EXPIRED"       // the pending window passed before approval
	CodeApprovalSelf    = "APPROVAL_SELF_APPROVAL" // the requester tried to approve (or reject) their own escalation
	CodeApprovalReject  = "APPROVAL_REJECTED"      // an approver rejected the escalation
	DefaultDecisionTTL  = 60 * time.Second
	DefaultStageTimeout = time.Second
	DefaultAuditTimeout = 5 * time.Second
	// DefaultPendingTTL is how long an escalation may wait for approval. It is
	// separate from the request's own freshness TTL (≤5 min, checked at the
	// gateway): approval ignores the request TTL but enforces this window.
	DefaultPendingTTL = 15 * time.Minute
)

// Config wires an Engine. Every component except Enrichers is required.
type Config struct {
	Decoders     []Decoder
	Enrichers    []Enricher
	Policy       Policy
	Limiter      Limiter
	Signer       Signer
	Audit        AuditLog
	DecisionTTL  time.Duration // default 60s, at most model.MaxTTL
	StageTimeout time.Duration // per component call; default 1s
	// AuditTimeout bounds each write that records a decision or a state
	// change (audit append, Commit, Release). Those writes run detached from
	// the request's context: a client that disconnects mid-request must not
	// be able to leave a decision unaudited. Default 5s.
	AuditTimeout time.Duration
	Clock        func() time.Time
	Logger       *slog.Logger
	// Pending persists escalations awaiting approval (CS-151/152). nil disables
	// approvals; an escalation is then returned but never recorded for approval.
	Pending PendingStore
	// PendingTTL is how long an escalation may wait for approval before it is
	// refused. Default DefaultPendingTTL (15m).
	PendingTTL time.Duration
}

// PendingEscalation is an escalated request and its lifecycle (CS-151/152).
// Records are kept once resolved, so GET /v1/decisions/{id} can report the
// outcome; every state change is written with its audit record.
type PendingEscalation struct {
	Request  model.ActionRequest `json:"request"`
	Reasons  []string            `json:"reasons"` // the escalated policy IDs an approver must cover
	IssuedAt time.Time           `json:"issued_at"`
	// RequestedBy is the KeyID of the identity that submitted the request, so
	// the same identity cannot also approve or reject it (CS-152 separation of
	// duties). Empty when auth is off (loopback dev), which disables the check.
	RequestedBy string                `json:"requested_by,omitempty"`
	State       model.EscalationState `json:"state"`
	// Decision is the escalate decision while pending, then the final one.
	Decision   *model.Decision `json:"decision,omitempty"`
	ResolvedBy string          `json:"resolved_by,omitempty"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
}

// PendingStore records escalations by request ID. Put writes the record and,
// when rec is non-nil, its audit record in ONE transaction (LLD §11): an
// escalation is created, approved, rejected or expired only if it is audited.
type PendingStore interface {
	Put(ctx context.Context, e PendingEscalation, rec *model.AuditEntry) error
	Get(ctx context.Context, id string) (PendingEscalation, bool, error)
}

// Execute runs when an approval's re-run allows (gatekeeper mode: sign the
// transaction and commit the reservation). It returns the final decision: the
// allow, with the signed transaction, or a deny if execution failed.
type Execute func(ctx context.Context, d model.Decision, req model.ActionRequest) model.Decision

// ErrNoPending (re-exported from model) means no escalation with that id is
// visible to the caller.
var ErrNoPending = model.ErrNoPending

// Engine implements gateway.Evaluator.
type Engine struct {
	cfg Config
	// escMu serialises escalation state changes (approve, reject, expiry), so
	// two approvers cannot both resolve one escalation.
	escMu sync.Mutex
	// unauditedDenials counts denials that could not be audited. Failing
	// closed is right, but it must never be silent.
	unauditedDenials atomic.Uint64
}

// Counters are the engine's metrics, for /metrics.
func (e *Engine) Counters() map[string]uint64 {
	return map[string]uint64{"stopbar_audit_unavailable_denials_total": e.unauditedDenials.Load()}
}

// unaudited records a denial that could not be audited, loudly.
func (e *Engine) unaudited(requestID string, err error) {
	e.unauditedDenials.Add(1)
	e.cfg.Logger.Error("UNAUDITED DENIAL: audit log unavailable; failing closed", "severity", "high",
		"request_id", requestID, "err", err, "metric", "stopbar_audit_unavailable_denials_total")
}

// New validates cfg. A missing component is a configuration error, not a
// silent pass-through.
func New(cfg Config) (*Engine, error) {
	var missing []string
	if len(cfg.Decoders) == 0 {
		missing = append(missing, "Decoders")
	}
	for name, c := range map[string]any{"Policy": cfg.Policy, "Limiter": cfg.Limiter, "Signer": cfg.Signer, "Audit": cfg.Audit} {
		if c == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("engine: missing components: %v", missing)
	}
	if cfg.DecisionTTL == 0 {
		cfg.DecisionTTL = DefaultDecisionTTL
	}
	if cfg.DecisionTTL < 0 || cfg.DecisionTTL > model.MaxTTL {
		return nil, fmt.Errorf("engine: DecisionTTL must be in (0, %s]", model.MaxTTL)
	}
	if cfg.StageTimeout <= 0 {
		cfg.StageTimeout = DefaultStageTimeout
	}
	if cfg.AuditTimeout <= 0 {
		cfg.AuditTimeout = DefaultAuditTimeout
	}
	if cfg.PendingTTL <= 0 {
		cfg.PendingTTL = DefaultPendingTTL
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Engine{cfg: cfg}, nil
}

// stageError carries the reason code of the stage that failed.
type stageError struct {
	code string
	err  error
}

func (e *stageError) Error() string { return e.code + ": " + e.err.Error() }

// Unwrap lets callers match the domain error (e.g. ErrUnknownReservation).
func (e *stageError) Unwrap() error { return e.err }

func failed(code string, err error) *stageError { return &stageError{code, err} }

// call runs fn with the stage timeout, converting a panic or a timeout into
// an error. A component that ignores ctx is abandoned on timeout; callers
// must not read state that fn may still be writing.
func (e *Engine) call(ctx context.Context, fn func(context.Context) error) error {
	return e.callWithin(ctx, e.cfg.StageTimeout, fn)
}

// record runs a write that records a decision or a state change that has
// already happened. It keeps the request's values but not its cancellation,
// and has its own timeout, so a disconnecting caller can't stop the record.
func (e *Engine) record(ctx context.Context, fn func(context.Context) error) error {
	return e.callWithin(context.WithoutCancel(ctx), e.cfg.AuditTimeout, fn)
}

func (e *Engine) callWithin(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("panic: %v\n%s", p, debug.Stack())
			}
		}()
		done <- fn(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("timed out after %s: %w", e.cfg.StageTimeout, ctx.Err())
	}
}

// Evaluate never returns an error; the error result exists to satisfy
// gateway.Evaluator.
func (e *Engine) Evaluate(ctx context.Context, req model.ActionRequest) (d model.Decision, _ error) {
	now := e.cfg.Clock()
	defer func() {
		if p := recover(); p != nil {
			e.cfg.Logger.Error("engine panic", "request_id", req.ID, "panic", p, "stack", string(debug.Stack()))
			d = e.deny(req.ID, now, "", failed(CodeEngine, fmt.Errorf("internal error")))
		}
	}()
	return e.evaluate(ctx, req, now, nil, ""), nil
}

// Approve re-evaluates a pending escalation (CS-151/152) and returns the
// result; it implements gateway.Approver for advisory mode, where an approved
// allow returns the decision token. See ApproveWith.
func (e *Engine) Approve(ctx context.Context, id, approver string) (model.Decision, error) {
	return e.ApproveWith(ctx, id, approver, nil)
}

// ApproveWith re-evaluates a pending escalation against current state
// (CS-151/152): enrich, policy and the limiter all run again, and the
// escalation reasons the approver covers are waived. If nothing else now
// denies and the caps still hold, the outcome becomes allow (signed and
// reserved like any allow), exec (if any) executes it, and the escalation is
// resolved, audited in the same transaction. If a new rule denies, a new
// escalation appears, or a cap has since filled, the decision is returned and
// the escalation stays pending, so the caller can see why and retry.
//
// It returns ErrNoPending for an id the caller cannot see (unknown, or another
// tenant's) and model.ErrResolved once the escalation is allowed, denied or
// expired. Approving after the window has passed resolves it as expired and
// returns that deny.
func (e *Engine) ApproveWith(ctx context.Context, id, approver string, exec Execute) (model.Decision, error) {
	e.escMu.Lock()
	defer e.escMu.Unlock()
	now := e.cfg.Clock()
	pe, d, err := e.openPending(ctx, id, approver, now)
	if err != nil || d != nil {
		return deref(d), err
	}
	approved := make(map[string]bool, len(pe.Reasons))
	for _, r := range pe.Reasons {
		approved[r] = true
	}
	out := e.evaluate(ctx, pe.Request, now, approved, approver)
	if out.Outcome != model.Allow {
		return out, nil // still pending: the approver can see why, and retry
	}
	if exec != nil {
		out = exec(ctx, out, pe.Request)
	}
	state := model.EscalationAllowed
	if out.Outcome != model.Allow {
		state = model.EscalationDenied
	}
	body := map[string]any{"request_id": id, "state": state, "approver": approver, "decision": out}
	if err := e.resolve(ctx, &pe, state, out, approver, now, model.AuditApproval, body); err != nil {
		// The allow happened (reserved, perhaps signed and committed) but its
		// resolution is not recorded: fail closed. The signed bytes never
		// leave; a reservation lapses with its TTL and a commit stays counted.
		e.unaudited(id, err)
		return e.denyWith(out, failed(CodeAudit, err)), nil
	}
	return out, nil
}

// Reject resolves a pending escalation as denied (CS-151/152, LLD §9 step 4:
// any reject → deny). The approver identity is in the audit record, written in
// the same transaction as the state change. The requester may not reject
// their own escalation; errors are as for ApproveWith.
func (e *Engine) Reject(ctx context.Context, id, approver string) (model.Decision, error) {
	e.escMu.Lock()
	defer e.escMu.Unlock()
	now := e.cfg.Clock()
	pe, d, err := e.openPending(ctx, id, approver, now)
	if err != nil || d != nil {
		return deref(d), err
	}
	out := e.deny(id, now, pe.payloadHash(), failed(CodeApprovalReject, fmt.Errorf("rejected by %q", approver)))
	body := map[string]any{"request": pe.Request, "decision": out, "approver": approver}
	if err := e.resolve(ctx, &pe, model.EscalationDenied, out, approver, now, model.AuditDecision, body); err != nil {
		e.unaudited(id, err)
		return model.Decision{}, err // nothing changed: still pending
	}
	return out, nil
}

// Status reports an escalation's lifecycle for GET /v1/decisions/{id}
// (CS-152). A pending escalation whose window has passed is resolved as
// expired first (a deny, audited), so the polled state and the log agree.
func (e *Engine) Status(ctx context.Context, id string) (model.EscalationStatus, error) {
	e.escMu.Lock()
	defer e.escMu.Unlock()
	pe, _, err := e.loadPending(ctx, id, e.cfg.Clock())
	if err != nil {
		return model.EscalationStatus{}, err
	}
	return model.EscalationStatus{
		RequestID: pe.Request.ID, State: pe.State, Reasons: pe.Reasons, Request: pe.Request,
		CreatedAt: pe.IssuedAt, ExpiresAt: pe.IssuedAt.Add(e.cfg.PendingTTL),
		ResolvedBy: pe.ResolvedBy, ResolvedAt: pe.ResolvedAt, Decision: pe.Decision,
	}, nil
}

// Owner reports who a reservation was made for (tenant, agent), so the gateway
// can scope commit and release to the requester (CS-105).
func (e *Engine) Owner(id string) (tenant, agent string, ok bool) { return e.cfg.Limiter.Owner(id) }

// openPending loads a still-pending escalation for approve or reject. It
// returns a decision instead when the attempt itself is refused: the window
// passed just now (resolved as expired) or the requester is trying to act on
// their own escalation (audited; the record stays pending for someone else).
func (e *Engine) openPending(ctx context.Context, id, approver string, now time.Time) (PendingEscalation, *model.Decision, error) {
	pe, expired, err := e.loadPending(ctx, id, now)
	switch {
	case err != nil:
		return pe, nil, err
	case expired:
		return pe, pe.Decision, nil
	case pe.State != model.EscalationPending:
		return pe, nil, model.ErrResolved
	case approver != "" && approver == pe.RequestedBy:
		d := e.deny(id, now, pe.payloadHash(), failed(CodeApprovalSelf, fmt.Errorf("the requester may not resolve their own escalation")))
		e.auditRefusal(ctx, pe.Request, d)
		return pe, &d, nil
	}
	return pe, nil, nil
}

// loadPending returns the escalation for id if the caller may see it (an
// authenticated caller only sees its own tenant's), expiring it first if its
// approval window has passed. expired reports that this call expired it.
func (e *Engine) loadPending(ctx context.Context, id string, now time.Time) (pe PendingEscalation, expired bool, err error) {
	if e.cfg.Pending == nil {
		return pe, false, errors.New("engine: approvals are not enabled")
	}
	pe, ok, err := e.cfg.Pending.Get(ctx, id)
	if err != nil {
		return pe, false, err
	}
	if caller, authed := auth.FromContext(ctx); !ok || (authed && caller.Tenant != pe.Request.Tenant) {
		return PendingEscalation{}, false, ErrNoPending
	}
	if pe.State == "" {
		pe.State = model.EscalationPending
	}
	// An escalation may wait only PendingTTL for approval. This is the pending
	// window, not the request's own freshness TTL, which approval deliberately
	// ignores (a human takes longer than 5 minutes). Timeout → deny.
	if pe.State == model.EscalationPending && now.Sub(pe.IssuedAt) > e.cfg.PendingTTL {
		d := e.deny(id, now, pe.payloadHash(), failed(CodeApprovalExpired, fmt.Errorf("escalation expired after %s", e.cfg.PendingTTL)))
		body := map[string]any{"request": pe.Request, "decision": d}
		if err := e.resolve(ctx, &pe, model.EscalationExpired, d, "", now, model.AuditDecision, body); err != nil {
			e.unaudited(id, err)
			return PendingEscalation{}, false, err
		}
		return pe, true, nil
	}
	return pe, false, nil
}

// resolve moves an escalation to its final state and writes its audit record
// in the same transaction. On failure pe is left unchanged.
func (e *Engine) resolve(ctx context.Context, pe *PendingEscalation, state model.EscalationState, d model.Decision, by string, now time.Time, typ model.AuditRecordType, body map[string]any) error {
	next := *pe
	next.State, next.Decision, next.ResolvedBy, next.ResolvedAt = state, &d, by, &now
	rec := &model.AuditEntry{Type: typ, Body: addIdentity(ctx, body)}
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Pending.Put(ctx, next, rec) }); err != nil {
		return err
	}
	*pe = next
	return nil
}

func (pe PendingEscalation) payloadHash() string {
	if pe.Decision != nil {
		return pe.Decision.PayloadHash
	}
	ph, _ := decision.PayloadHash(pe.Request.Action) // best-effort binding for the audit record
	return ph
}

func deref(d *model.Decision) model.Decision {
	if d == nil {
		return model.Decision{}
	}
	return *d
}

// auditRefusal records an approval refusal (self-approval) as a decision audit
// record. The outcome is already deny, so a failed audit still fails closed;
// it is counted, loudly, as an unaudited denial.
func (e *Engine) auditRefusal(ctx context.Context, req model.ActionRequest, d model.Decision) {
	body := addIdentity(ctx, map[string]any{"request": req, "decision": d})
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Audit.Append(ctx, model.AuditDecision, body) }); err != nil {
		e.unaudited(req.ID, err)
	}
}

// addIdentity puts the authenticated caller (if any) into an audit body, so
// every audit record carries the identity. It goes INSIDE the body, leaving
// audit-hash v1 unchanged (spec/audit-hash-v1.md).
func addIdentity(ctx context.Context, body map[string]any) map[string]any {
	if id, ok := auth.FromContext(ctx); ok {
		body["identity"] = id
	}
	return body
}

// policyIDs are the policy ids of a decision's reasons (the escalation reasons
// an approver must cover).
func policyIDs(reasons []model.Reason) []string {
	ids := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if r.PolicyID != "" {
			ids = append(ids, r.PolicyID)
		}
	}
	return ids
}

// allApproved reports whether every reason's policy id was approved (and there
// is at least one). A new escalation reason the approver has not seen fails it.
func allApproved(reasons []model.Reason, approved map[string]bool) bool {
	if len(reasons) == 0 {
		return false
	}
	for _, r := range reasons {
		if !approved[r.PolicyID] {
			return false
		}
	}
	return true
}

func (e *Engine) evaluate(ctx context.Context, req model.ActionRequest, now time.Time, approved map[string]bool, approver string) model.Decision {
	audit := func(d model.Decision, extra map[string]any) model.Decision {
		body := addIdentity(ctx, map[string]any{"request": req, "decision": d})
		for k, v := range extra {
			body[k] = v
		}
		err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Audit.Append(ctx, model.AuditDecision, body) })
		if err == nil {
			return d
		}
		e.unaudited(req.ID, err)
		return e.deny(req.ID, now, d.PayloadHash, failed(CodeAudit, fmt.Errorf("audit append failed")), d.Reasons...)
	}

	// normalize: bind the payload before anything else looks at it.
	payloadHash, err := decision.PayloadHash(req.Action)
	if err != nil {
		return audit(e.deny(req.ID, now, "", failed(CodeNormalize, err)), nil)
	}

	// decode
	intent, serr := e.decode(ctx, req.Action, payloadHash)
	if serr != nil {
		return audit(e.deny(req.ID, now, payloadHash, serr), nil)
	}

	// enrich
	er, serr := e.enrich(ctx, req, intent, payloadHash)
	if serr != nil {
		return audit(e.deny(req.ID, now, payloadHash, serr), map[string]any{"intent": intent})
	}
	ctxRecord := map[string]any{"context": er}

	// policy
	var pr PolicyResult
	if err := e.call(ctx, func(ctx context.Context) (err error) { pr, err = e.cfg.Policy.Evaluate(ctx, er); return }); err != nil {
		return audit(e.deny(req.ID, now, payloadHash, failed(CodePolicyFail, err)), ctxRecord)
	}
	if err := checkPolicyResult(pr); err != nil {
		return audit(e.deny(req.ID, now, payloadHash, failed(CodePolicyFail, err)), ctxRecord)
	}
	reasons := make([]model.Reason, len(pr.Reasons))
	for i, r := range pr.Reasons {
		if r.Code == "" {
			r.Code = CodePolicy
		}
		reasons[i] = r
	}
	d := model.Decision{
		RequestID: req.ID, Outcome: pr.Outcome, Reasons: reasons,
		PolicyBundleHash: pr.BundleHash, PayloadHash: payloadHash,
		Approvals: []model.Approval{}, IssuedAt: now, ExpiresAt: now.Add(e.cfg.DecisionTTL),
	}
	if pr.Outcome == model.Escalate {
		switch {
		case approved != nil && allApproved(reasons, approved):
			// CS-151: the approver covers every escalation reason this re-run
			// produced → allow. The allow path below re-reserves the caps, so a
			// cap that has filled since the escalation still blocks it.
			d.Outcome, d.Reasons = model.Allow, []model.Reason{}
			d.Approvals = []model.Approval{{Approver: approver, At: now}}
		case approved == nil && e.cfg.Pending != nil:
			// CS-152: record the escalation so `stopbar approve <id>` can re-run it,
			// with the requester's identity so it cannot also approve itself. The
			// record and the escalate decision's audit record are one transaction.
			pe := PendingEscalation{Request: req, Reasons: policyIDs(reasons), IssuedAt: now,
				State: model.EscalationPending, Decision: &d}
			if rid, ok := auth.FromContext(ctx); ok {
				pe.RequestedBy = rid.KeyID
			}
			rec := &model.AuditEntry{Type: model.AuditDecision, Body: addIdentity(ctx, map[string]any{"request": req, "decision": d, "context": er})}
			if perr := e.record(ctx, func(ctx context.Context) error { return e.cfg.Pending.Put(ctx, pe, rec) }); perr != nil {
				e.unaudited(req.ID, perr)
				return audit(e.deny(req.ID, now, payloadHash, failed(CodeAudit, perr)), ctxRecord)
			}
			return d
		}
	}
	if d.Outcome != model.Allow {
		// Escalations and denies do not reserve: approval (CS-151) re-runs the
		// limiter, so pending escalations cannot tie up caps.
		return audit(d, ctxRecord)
	}

	// sign first: it changes no state. The token claims reservation_id, and
	// the reservation is made below, in the same transaction as the
	// decision's audit record. If that fails, the token never leaves.
	id := req.ID
	d.ReservationID = &id
	var token string
	if err := e.call(ctx, func(ctx context.Context) (err error) { token, err = e.cfg.Signer.Sign(ctx, req, d); return }); err != nil || token == "" {
		if err == nil {
			err = errors.New("signer returned an empty token")
		}
		d.ReservationID = nil
		return audit(e.denyWith(d, failed(CodeSigner, err)), ctxRecord)
	}
	d.Token = token

	// limiter: reserve + audit the allow, atomically.
	rec := &model.AuditEntry{Type: model.AuditDecision, Body: addIdentity(ctx, map[string]any{"request": req, "decision": d, "context": er})}
	if err := e.call(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Reserve(ctx, id, er, e.cfg.DecisionTTL, rec) }); err != nil {
		e.release(ctx, id, "reserve failed or timed out") // a timed-out Reserve may still land
		if errors.Is(err, ErrAuditUnavailable) {
			e.unaudited(req.ID, err)
			out := e.denyWith(d, failed(CodeAudit, err))
			return audit(out, ctxRecord) // best effort: the store may be back
		}
		return audit(e.denyWith(d, limiterFailure(err)), ctxRecord)
	}
	return d
}

func (e *Engine) decode(ctx context.Context, a model.Action, payloadHash string) (model.IntentSummary, *stageError) {
	var dec Decoder
	for _, d := range e.cfg.Decoders {
		if d.Supports(a) {
			dec = d
			break
		}
	}
	if dec == nil {
		return model.IntentSummary{}, failed(CodeDecoder, fmt.Errorf("no decoder for action kind %q", a.Kind))
	}
	var intent model.IntentSummary
	if err := e.call(ctx, func(ctx context.Context) (err error) { intent, err = dec.Decode(ctx, a); return }); err != nil {
		return model.IntentSummary{}, failed(CodeDecoder, err)
	}
	if intent.PayloadHash != "" && intent.PayloadHash != payloadHash {
		return model.IntentSummary{}, failed(CodeDecoder, errors.New("decoder rendered a different payload than the one bound"))
	}
	intent.PayloadHash = payloadHash
	if intent.Flags == nil {
		intent.Flags = []string{}
	}
	return intent, nil
}

// enrich runs the enrichers in order, then checks they only added: the
// action and intent are unchanged, and every provenance label is still in
// the taint set. A timed-out enricher may still be writing to its request,
// so on failure the partially enriched request is dropped, never read.
func (e *Engine) enrich(ctx context.Context, req model.ActionRequest, intent model.IntentSummary, payloadHash string) (model.EnrichedRequest, *stageError) {
	er := &model.EnrichedRequest{
		Request:  req,
		Intent:   intent,
		Taint:    slices.Clone(req.Provenance.Labels),
		Velocity: map[string]model.Velocity{},
	}
	er.Request.Provenance.Labels = slices.Clone(req.Provenance.Labels)
	for i, en := range e.cfg.Enrichers {
		if err := e.call(ctx, func(ctx context.Context) error { return en.Enrich(ctx, er) }); err != nil {
			return model.EnrichedRequest{}, failed(CodeEnrich, fmt.Errorf("enricher %d (%T): %w", i, en, err))
		}
	}
	if ph, err := decision.PayloadHash(er.Request.Action); err != nil || ph != payloadHash || er.Intent.PayloadHash != payloadHash {
		return model.EnrichedRequest{}, failed(CodeEnrich, errors.New("an enricher modified the action or intent"))
	}
	for _, l := range req.Provenance.Labels {
		if !slices.Contains(er.Taint, l) {
			return model.EnrichedRequest{}, failed(CodeEnrich, fmt.Errorf("an enricher removed taint label %q (taint may only be added)", l))
		}
	}
	return *er, nil
}

var reSHA256 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func checkPolicyResult(pr PolicyResult) error {
	switch pr.Outcome {
	case model.Allow, model.Deny, model.Escalate:
	default:
		return fmt.Errorf("policy returned unknown outcome %q", pr.Outcome)
	}
	if pr.Outcome != model.Allow && len(pr.Reasons) == 0 {
		return fmt.Errorf("policy returned %s without reasons", pr.Outcome)
	}
	if !reSHA256.MatchString(pr.BundleHash) {
		return errors.New("policy result has no valid bundle hash")
	}
	return nil
}

func limiterFailure(err error) *stageError {
	switch {
	case errors.Is(err, ErrCapExceeded):
		return failed(CodeCapExceeded, err)
	case errors.Is(err, ErrCircuitOpen):
		return failed(CodeCircuitOpen, err)
	default:
		return failed(CodeLimiter, err)
	}
}

// release is best-effort: an unreleased reservation still expires with the
// decision TTL.
func (e *Engine) release(ctx context.Context, id, reason string) {
	rec := &model.AuditEntry{Type: model.AuditRelease, Body: map[string]any{"request_id": id, "reason": reason}}
	err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Release(ctx, id, rec) })
	if errors.Is(err, ErrUnknownReservation) || errors.Is(err, ErrReservationExpired) {
		return // nothing was held
	}
	if err != nil {
		e.cfg.Logger.Warn("release after failed allow path", "request_id", id, "err", err)
	}
}

// deny builds a fail-closed deny. Component errors are logged, not returned:
// reasons carry the code and a fixed message so internals never leak.
func (e *Engine) deny(requestID string, now time.Time, payloadHash string, se *stageError, keep ...model.Reason) model.Decision {
	e.cfg.Logger.Warn("fail closed", "request_id", requestID, "code", se.code, "err", se.err)
	reasons := append(slices.Clone(keep), model.Reason{Code: se.code, Message: publicMessage(se)})
	return model.Decision{
		RequestID: requestID, Outcome: model.Deny, Reasons: reasons, PayloadHash: payloadHash,
		Approvals: []model.Approval{}, IssuedAt: now, ExpiresAt: now.Add(e.cfg.DecisionTTL),
	}
}

// denyWith turns an in-flight allow into a deny, keeping its bindings.
func (e *Engine) denyWith(d model.Decision, se *stageError) model.Decision {
	out := e.deny(d.RequestID, d.IssuedAt, d.PayloadHash, se)
	out.PolicyBundleHash = d.PolicyBundleHash
	return out
}

func publicMessage(se *stageError) string {
	switch se.code {
	case CodeCapExceeded:
		return "value or velocity cap exceeded"
	case CodeCircuitOpen:
		return "circuit breaker open"
	case CodeApprovalExpired:
		return "the approval window has expired"
	case CodeApprovalSelf:
		return "the requester may not approve or reject their own request"
	case CodeApprovalReject:
		return "an approver rejected the request"
	case CodeNormalize:
		if errors.Is(se.err, decision.ErrNoBinding) {
			return "action kind cannot be bound to a decision in v1"
		}
		return "action could not be normalised"
	default:
		return "component failure; failing closed"
	}
}

// Commit records that the allowed action was broadcast (or, in gatekeeper
// mode, signed). The commit and its audit record are one transaction.
func (e *Engine) Commit(ctx context.Context, requestID, txRef string) error {
	rec := &model.AuditEntry{Type: model.AuditCommit, Body: addIdentity(ctx, map[string]any{"request_id": requestID, "tx_ref": txRef})}
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Commit(ctx, requestID, txRef, rec) }); err != nil {
		if errors.Is(err, ErrAuditUnavailable) {
			return failed(CodeAudit, err)
		}
		return failed(CodeLimiter, err)
	}
	return nil
}

// Release abandons an allowed action and frees its reservation. The reason
// (e.g. "client", or why a signer adapter refused) is audited with it.
func (e *Engine) Release(ctx context.Context, requestID, reason string) error {
	rec := &model.AuditEntry{Type: model.AuditRelease, Body: addIdentity(ctx, map[string]any{"request_id": requestID, "reason": reason})}
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Release(ctx, requestID, rec) }); err != nil {
		if errors.Is(err, ErrAuditUnavailable) {
			return failed(CodeAudit, err)
		}
		return failed(CodeLimiter, err)
	}
	return nil
}
