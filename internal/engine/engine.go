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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
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
	// Void releases a reservation even if committed: only for an evaluation
	// whose answer never left stopbard (Engine.Abandon, CS-197).
	Void(ctx context.Context, id string, rec *model.AuditEntry) error
	// Owner reports the tenant and agent a reservation was made for, so
	// commit/release over HTTP (CS-105) can be scoped to the requester.
	Owner(id string) (tenant, agent string, ok bool)
}

// Breaker reports whether a tenant's circuit breaker is open (CS-124, LLD
// §7.3). While it is, every evaluation for the tenant is denied CIRCUIT_OPEN
// before decode or policy run, so escalations and approvals stop too. An
// error is FAIL_CLOSED_LIMITER. The limiter trips it (Reserve returns
// ErrCircuitOpen) and only a quorum of approvers resets it.
type Breaker interface {
	CircuitOpen(ctx context.Context, tenant string) (bool, error)
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
// It needs the request for the token's tenant and nonce claims, and the
// authenticated requester identity, which decision-token v2 binds (CS-103).
// That identity is the zero Identity when auth is off.
type Signer interface {
	Sign(ctx context.Context, requester auth.Identity, req model.ActionRequest, d model.Decision) (token string, err error)
}

// AuditLog appends to the hash chain (CS-171).
type AuditLog interface {
	Append(ctx context.Context, typ model.AuditRecordType, body any) error
}

// Reason codes (LLD §12).
const (
	CodePolicy     = "POLICY"
	CodeNormalize  = "FAIL_CLOSED_NORMALIZE"
	CodeDecoder    = "FAIL_CLOSED_DECODER"
	CodeEnrich     = "FAIL_CLOSED_ENRICH"
	CodePolicyFail = "FAIL_CLOSED_POLICY"
	CodeLimiter    = "FAIL_CLOSED_LIMITER"
	CodeSigner     = "FAIL_CLOSED_SIGNER"
	CodeAudit      = "FAIL_CLOSED_AUDIT"
	// CodeStore: the evaluation's state transaction did not become durable
	// within the gateway's store timeout (CS-197, LLD §12). The gateway answers
	// it; Abandon resolves an escalation that landed late with it.
	CodeStore           = "FAIL_CLOSED_STORE"
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
	Decoders  []Decoder
	Enrichers []Enricher
	Policy    Policy
	Limiter   Limiter
	// Breaker is the tenant circuit breaker (CS-124). nil: the engine uses
	// Limiter if it implements Breaker, and otherwise has no breaker check.
	Breaker      Breaker
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
	// Approvers is the configured Ed25519 approver public keys (CS-151,
	// spec/approval-signature-v1.md) an escalation approval or reject
	// signature is checked against. nil disables approvals entirely: Approve
	// and Reject refuse every signature.
	Approvers *approval.KeySet
	// ApprovalQuorum is M in the M-of-N escalation approval: distinct
	// approver OWNERS needed (CS-151, internal/approval.Tally; two keys
	// configured with the same owner count once). 0 means
	// model.MinBreakerQuorum (2). stopbard enforces the production floor
	// (approval.ValidateQuorum) before it ever builds this Config; tests may
	// set 1 directly for a single-signer flow.
	ApprovalQuorum int
	// Alerts records every reject veto (CS-151): a high-severity log line
	// and the stopbar_approval_rejects_total counter. nil: one is created
	// internally, but then its counts are not reachable by the caller for
	// rendering at /metrics — supply one to read Alerts.Counters().
	Alerts *approval.Alerts
}

// PendingEscalation is an escalated request and its lifecycle (CS-151/152).
// Records are kept once resolved, so GET /v1/decisions/{id} can report the
// outcome; every state change is written with its audit record.
type PendingEscalation struct {
	Request  model.ActionRequest `json:"request"`
	Reasons  []string            `json:"reasons"` // the escalated policy IDs an approver must cover
	IssuedAt time.Time           `json:"issued_at"`
	// Requester is the authenticated identity that submitted the request. The
	// same key cannot also approve it (CS-152 separation of duties), and an
	// approved allow's token binds it, not the approver (decision-token v2).
	// Zero when auth is off (loopback dev), which disables the SoD check.
	Requester auth.Identity         `json:"requester"`
	State     model.EscalationState `json:"state"`
	// Decision is the escalate decision while pending, then the final one.
	Decision   *model.Decision `json:"decision,omitempty"`
	ResolvedBy string          `json:"resolved_by,omitempty"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
	// Votes are the signed approve/reject votes verified so far (CS-151),
	// replayed into a fresh approval.Tally on every Approve/Reject call —
	// Tally itself persists nothing, this is the durable record (LLD §11).
	// A vote that resolves the Tally (quorum met, or a reject) is appended
	// only once that outcome's side effects (re-run, signing) have also
	// succeeded; one that leaves it Pending is appended on its own.
	Votes []approval.Vote `json:"votes,omitempty"`
}

// PendingStore records escalations by request ID. Put writes the record and,
// when rec is non-nil, its audit record in ONE transaction (LLD §11): an
// escalation is created, approved, rejected or expired only if it is audited.
type PendingStore interface {
	Put(ctx context.Context, e PendingEscalation, rec *model.AuditEntry) error
	Get(ctx context.Context, id string) (PendingEscalation, bool, error)
}

// Execute runs when an approval's re-run allows (gatekeeper mode: sign the
// transaction and commit the reservation). requester is the identity that
// submitted the request, which the token binds (decision-token v2), not the
// approver in ctx. It returns the final decision: the allow, with the signed
// transaction, or a deny if execution failed.
type Execute func(ctx context.Context, d model.Decision, req model.ActionRequest, requester auth.Identity) model.Decision

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
	if cfg.ApprovalQuorum <= 0 {
		cfg.ApprovalQuorum = model.MinBreakerQuorum
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if b, ok := cfg.Limiter.(Breaker); ok && cfg.Breaker == nil {
		cfg.Breaker = b // the limiter that trips the breaker also enforces it
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Alerts == nil {
		cfg.Alerts = approval.NewAlerts(cfg.Logger)
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
//
// A stage that times out is abandoned, not stopped: its goroutine may still
// run. So fn must capture only values the caller will not change afterwards
// (copies), and return results through stage, never by writing to a
// variable the caller reads (CS-197: a timed-out Sign once read d while
// evaluate rewrote it).
func (e *Engine) call(ctx context.Context, fn func(context.Context) error) error {
	_, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (struct{}, error) { return struct{}{}, fn(ctx) })
	return err
}

// record runs a write that records a decision or a state change that has
// already happened. It keeps the request's values but not its cancellation,
// and has its own timeout, so a disconnecting caller can't stop the record.
func (e *Engine) record(ctx context.Context, fn func(context.Context) error) error {
	_, err := stage(context.WithoutCancel(ctx), e.cfg.AuditTimeout, func(ctx context.Context) (struct{}, error) { return struct{}{}, fn(ctx) })
	return err
}

// stage runs fn in its own goroutine under timeout and returns its result,
// or an error on timeout or panic. The result comes back only through the
// channel, so a goroutine abandoned at the timeout never writes to anything
// the caller reads. Inputs are the caller's job: see call.
func stage[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- result{err: fmt.Errorf("panic: %v\n%s", p, debug.Stack())}
			}
		}()
		v, err := fn(ctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("timed out after %s: %w", timeout, ctx.Err())
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
	requester, _ := auth.FromContext(ctx)
	return e.evaluate(ctx, req, now, nil, nil, requester), nil
}

// Approve verifies sig — an Ed25519-signed escalation-approval envelope
// (spec/approval-signature-v1.md §2, decision "approve") — and adds its vote
// toward the escalation's quorum (CS-151). It implements gateway.Approver
// for advisory mode, where an approved allow returns the decision token. See
// ApproveWith.
func (e *Engine) Approve(ctx context.Context, id string, sig approval.SignedEscalation) (model.Decision, error) {
	return e.ApproveWith(ctx, id, sig, nil)
}

// ApproveWith verifies sig and adds its vote toward the escalation's quorum
// (CS-151, internal/approval.Tally: M distinct approver OWNERS, two keys
// with the same owner count once). Three outcomes:
//
//   - Pending (quorum not yet met): the vote is recorded, audited, and the
//     escalation's current (still-escalate) decision is returned unchanged.
//     Nothing is re-run yet — there is no point until quorum is reached.
//   - Rejected (this or any earlier vote was a `reject`): the escalation is
//     denied outright (LLD §9 step 4), audited, and alerted
//     (internal/approval.Alerts.Veto, stopbar_approval_rejects_total).
//   - Approved (quorum just met): enrich, policy and the limiter all run
//     again, and the escalation reasons every counted vote's owner covers
//     are waived. If nothing else now denies and the caps still hold, the
//     outcome becomes allow (signed and reserved like any allow), exec (if
//     any) executes it, and the escalation is resolved, audited in the same
//     transaction. If the re-run does **not** allow, nothing is persisted —
//     the quorum's votes are not spent on a failed attempt, so approvers
//     must resubmit (LLD §9 step 5: a re-run can still deny or escalate
//     against current state).
//
// A signature that fails verification (wrong escalation/payload, expired,
// unknown key, self-approval, posted to the wrong decision, …) resolves
// nothing: it is audited as a refused attempt and returns a deny decision,
// while the escalation stays pending for a valid vote. It returns
// ErrNoPending for an id the caller cannot see (unknown, or another
// tenant's), approval.ErrDuplicateVote for a second vote from an owner who
// already holds a live one, and model.ErrResolved once the escalation is
// allowed, denied or expired. Approving after the window has passed
// resolves it as expired and returns that deny.
func (e *Engine) ApproveWith(ctx context.Context, id string, sig approval.SignedEscalation, exec Execute) (model.Decision, error) {
	return e.submitVote(ctx, id, sig, approval.Approve, exec)
}

// Reject verifies sig — a signed escalation envelope with decision "reject"
// — and, being a valid vote, denies the escalation outright regardless of
// quorum (CS-151, LLD §9 step 4). Errors and the self-approval/expiry/
// already-resolved cases are as for ApproveWith.
func (e *Engine) Reject(ctx context.Context, id string, sig approval.SignedEscalation) (model.Decision, error) {
	return e.submitVote(ctx, id, sig, approval.Reject, nil)
}

// submitVote is the shared core of Approve and Reject: it verifies sig
// against the escalation's current state and the configured approver keys,
// replays the escalation's stored votes into a fresh approval.Tally, adds
// sig's vote, and acts on the result. wantDecision pins which decision this
// call's route expects; a signed envelope carrying the other decision is
// refused (posting to the wrong endpoint fails loudly, not silently doing
// the other thing).
func (e *Engine) submitVote(ctx context.Context, id string, sig approval.SignedEscalation, wantDecision string, exec Execute) (model.Decision, error) {
	e.escMu.Lock()
	defer e.escMu.Unlock()
	now := e.cfg.Clock()
	pe, d, err := e.openPending(ctx, id, now)
	if err != nil {
		return model.Decision{}, err
	}
	if d != nil {
		return *d, nil // the pending window passed just now: resolved as expired
	}

	refuse := func(code string, cause error) model.Decision {
		rd := e.deny(id, now, pe.payloadHash(), failed(approvalFailureCode(code), cause))
		e.auditRefusal(ctx, pe.Request, rd)
		return rd
	}
	if sig.Decision != wantDecision {
		return refuse(approval.CodeBadDecision, fmt.Errorf("this envelope carries decision %q, not %q", sig.Decision, wantDecision)), nil
	}
	if e.cfg.Approvers == nil {
		return model.Decision{}, errors.New("engine: no approver keys configured; approvals are disabled")
	}
	want := approval.EscalationWant{EscalationID: id, PayloadHash: pe.payloadHash(),
		RequesterKeyID: pe.Requester.KeyID, RequesterAgentID: pe.Requester.AgentID}
	k, verifyErr := approval.VerifyEscalation(e.cfg.Approvers, pe.Request.Tenant, sig, want, now)
	if verifyErr != nil {
		var ve *approval.VerifyError
		if errors.As(verifyErr, &ve) {
			return refuse(ve.Code, verifyErr), nil
		}
		return model.Decision{}, verifyErr
	}

	tally := approval.NewTally(e.cfg.ApprovalQuorum, pe.Requester.KeyID, pe.Requester.AgentID)
	for _, v := range pe.Votes {
		_, _ = tally.Add(v, now) // already verified when first stored; replay is deterministic
	}
	v := approval.VoteFromEscalation(k, sig)
	res, addErr := tally.Add(v, now)
	switch {
	case errors.Is(addErr, approval.ErrDuplicateVote):
		return model.Decision{}, approval.ErrDuplicateVote
	case addErr != nil:
		var ve *approval.VerifyError
		if errors.As(addErr, &ve) {
			return refuse(ve.Code, addErr), nil
		}
		return model.Decision{}, addErr // e.g. ErrAlreadyResolved: a genuine race
	}

	switch res.Outcome {
	case approval.Pending:
		pe.Votes = append(pe.Votes, v)
		rec := &model.AuditEntry{Type: model.AuditApproval, Body: addIdentity(ctx, map[string]any{
			"request_id": id, "event": "vote", "kid": v.Kid, "owner": v.Owner, "decision": v.Decision})}
		put := pe // a copy: the record goroutine may outlive its timeout
		if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Pending.Put(ctx, put, rec) }); err != nil {
			e.unaudited(id, err)
			return model.Decision{}, err
		}
		return deref(pe.Decision), nil

	case approval.Rejected:
		e.cfg.Alerts.Veto(pe.Request.Tenant, approval.VetoKindEscalation, *res.Veto)
		out := e.deny(id, now, pe.payloadHash(), failed(CodeApprovalReject, fmt.Errorf("rejected by %s", res.Veto.Kid)))
		pe.Votes = append(pe.Votes, v)
		body := map[string]any{"request": pe.Request, "decision": out, "veto": res.Veto}
		if err := e.resolve(ctx, &pe, model.EscalationDenied, out, res.Veto.Kid, now, model.AuditDecision, body); err != nil {
			e.unaudited(id, err)
			return model.Decision{}, err // nothing changed: still pending
		}
		return out, nil

	default: // approval.Approved
		approved := make(map[string]bool, len(pe.Reasons))
		for _, r := range pe.Reasons {
			approved[r] = true
		}
		approvals := make([]model.Approval, 0, len(res.Approvers))
		for _, counted := range tally.Live(now) {
			approvals = append(approvals, model.Approval{Approver: counted.Kid, At: now, Signature: counted.Sig})
		}
		out := e.evaluate(ctx, pe.Request, now, approved, approvals, pe.Requester)
		if out.Outcome != model.Allow {
			// Ephemeral: nothing is persisted, so this quorum's votes are not
			// spent on a failed attempt (LLD §9 step 5).
			return out, nil
		}
		if exec != nil {
			out = exec(ctx, out, pe.Request, pe.Requester)
		}
		state := model.EscalationAllowed
		if out.Outcome != model.Allow {
			state = model.EscalationDenied
		}
		pe.Votes = append(pe.Votes, v)
		body := map[string]any{"request_id": id, "state": state, "approvals": approvals, "decision": out}
		if err := e.resolve(ctx, &pe, state, out, v.Kid, now, model.AuditApproval, body); err != nil {
			// The allow happened (reserved, perhaps signed and committed) but its
			// resolution is not recorded: fail closed. The signed bytes never
			// leave; a reservation lapses with its TTL and a commit stays counted.
			e.unaudited(id, err)
			return e.denyWith(out, failed(CodeAudit, err)), nil
		}
		return out, nil
	}
}

// approvalFailureCode maps a spec §6 VerifyError code to an engine reason
// code. SELF_APPROVAL keeps the pre-CS-151 CodeApprovalSelf string exactly
// (the same concept, now enforced cryptographically); every other code is
// prefixed APPROVAL_SIG_ so it can never collide with an unrelated engine
// code that happens to share a bare name (e.g. CodeApprovalExpired, which
// means the pending window passed, not that a signature's own expiry did).
func approvalFailureCode(code string) string {
	if code == approval.CodeSelfApproval {
		return CodeApprovalSelf
	}
	return "APPROVAL_SIG_" + code
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
// returns a decision instead when the window passed just now (resolved as
// expired). Self-approval is checked later, cryptographically, against the
// verified signature's owner (approval.VerifyEscalation / Tally), not here.
func (e *Engine) openPending(ctx context.Context, id string, now time.Time) (PendingEscalation, *model.Decision, error) {
	pe, expired, err := e.loadPending(ctx, id, now)
	switch {
	case err != nil:
		return pe, nil, err
	case expired:
		return pe, pe.Decision, nil
	case pe.State != model.EscalationPending:
		return pe, nil, model.ErrResolved
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
	body := addIdentity(ctx, map[string]any{"decision": d})
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Audit.Append(ctx, model.AuditDecision, body) }); err != nil {
		e.unaudited(req.ID, err)
	}
}

// auditContext is the enriched context for a decision record, without its
// copy of the request: the request record (written with the consumed nonce,
// in the same transaction or earlier in the chain) holds the request, and the
// decision carries request_id and payload_hash (CS-197: smaller records).
func auditContext(er model.EnrichedRequest) map[string]any {
	b, err := json.Marshal(er)
	var m map[string]any
	if err != nil || json.Unmarshal(b, &m) != nil {
		return map[string]any{"marshal_error": fmt.Sprint(err)} // the record still lands: never lose the decision
	}
	delete(m, "request")
	return m
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

// evaluate runs the pipeline. requester is the authenticated identity that
// submitted req (from the gateway, or from the pending record on approval);
// the audit records carry the identity in ctx, which on approval is the
// approver's. approvals (CS-151: one per distinct owner that counted toward
// quorum, nil on a first evaluation) becomes the allow decision's Approvals
// verbatim if this re-run allows.
func (e *Engine) evaluate(ctx context.Context, req model.ActionRequest, now time.Time, approved map[string]bool, approvals []model.Approval, requester auth.Identity) model.Decision {
	audit := func(d model.Decision, extra map[string]any) model.Decision {
		body := addIdentity(ctx, map[string]any{"decision": d})
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

	// circuit breaker (CS-124): a halted tenant gets nothing evaluated.
	if e.cfg.Breaker != nil {
		tenant := req.Tenant
		open, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (bool, error) { return e.cfg.Breaker.CircuitOpen(ctx, tenant) })
		if err != nil {
			return audit(e.deny(req.ID, now, payloadHash, failed(CodeLimiter, err)), nil)
		}
		if open {
			return audit(e.deny(req.ID, now, payloadHash, failed(CodeCircuitOpen, fmt.Errorf("tenant %q circuit breaker is open", req.Tenant))), nil)
		}
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
	ctxRecord := map[string]any{"context": auditContext(er)}

	// policy
	erPolicy := cloneEnriched(er)
	pr, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (PolicyResult, error) { return e.cfg.Policy.Evaluate(ctx, erPolicy) })
	if err != nil {
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
			d.Approvals = approvals
		case approved == nil && e.cfg.Pending != nil:
			// CS-152: record the escalation so `stopbar approve <id>` can re-run it,
			// with the requester's identity so it cannot also approve itself. The
			// record and the escalate decision's audit record are one transaction.
			dc := d // the record goroutine gets its own copy of the decision
			pe := PendingEscalation{Request: req, Reasons: policyIDs(reasons), IssuedAt: now, Requester: requester,
				State: model.EscalationPending, Decision: &dc}
			rec := &model.AuditEntry{Type: model.AuditDecision, Body: addIdentity(ctx, map[string]any{"decision": d, "context": auditContext(er)})}
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
	signReq, signD := req, d
	signD.Reasons = slices.Clone(d.Reasons)
	token, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (string, error) { return e.cfg.Signer.Sign(ctx, requester, signReq, signD) })
	if err != nil || token == "" {
		if err == nil {
			err = errors.New("signer returned an empty token")
		}
		d.ReservationID = nil
		return audit(e.denyWith(d, failed(CodeSigner, err)), ctxRecord)
	}
	d.Token = token

	// limiter: reserve + audit the allow, atomically.
	rec := &model.AuditEntry{Type: model.AuditDecision, Body: addIdentity(ctx, map[string]any{"decision": d, "context": auditContext(er)})}
	erReserve := cloneEnriched(er)
	if err := e.call(ctx, func(ctx context.Context) error {
		return e.cfg.Limiter.Reserve(ctx, id, erReserve, e.cfg.DecisionTTL, rec)
	}); err != nil {
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
	intent, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (model.IntentSummary, error) { return dec.Decode(ctx, a) })
	if err != nil {
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
	er.Intent.Flags = slices.Clone(intent.Flags) // enrichers append; never into the caller's backing array
	for i, en := range e.cfg.Enrichers {
		// Each enricher works on its own copy, and its copy becomes the
		// request only if it finished in time: a timed-out enricher may still
		// be writing, but to a copy nobody reads.
		in := cloneEnriched(*er)
		out, err := stage(ctx, e.cfg.StageTimeout, func(ctx context.Context) (model.EnrichedRequest, error) {
			err := en.Enrich(ctx, &in)
			return in, err
		})
		if err != nil {
			return model.EnrichedRequest{}, failed(CodeEnrich, fmt.Errorf("enricher %d (%T): %w", i, en, err))
		}
		*er = out
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

// cloneEnriched copies er deeply enough that a stage working on the copy
// shares no slice or map the engine writes: taint, flags, labels, velocity.
func cloneEnriched(er model.EnrichedRequest) model.EnrichedRequest {
	c := er
	c.Taint = slices.Clone(er.Taint)
	c.Intent.Flags = slices.Clone(er.Intent.Flags)
	c.Request.Provenance.Labels = slices.Clone(er.Request.Provenance.Labels)
	c.Velocity = maps.Clone(er.Velocity)
	return c
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

// Abandon undoes what an evaluation left in state when its transaction landed
// after the gateway had already answered FAIL_CLOSED_STORE (CS-197, LLD §12).
// The caller never saw that answer's token or signed tx, so nothing was
// broadcast: the reservation is voided (released even if the gatekeeper
// committed it, audited as a release with event "void"), and an escalation
// still pending is resolved as a deny with FAIL_CLOSED_STORE, so no approver
// can act on a request whose requester was told no. Each step is a durable
// write of its own; if the store is still down it fails, and what remains is
// conservative (capacity held, counted as spent) and is logged.
func (e *Engine) Abandon(ctx context.Context, requestID string) {
	ctx = context.WithoutCancel(ctx)
	rec := &model.AuditEntry{Type: model.AuditRelease, Body: map[string]any{"request_id": requestID, "event": "void",
		"reason": "state landed after the gateway answered " + CodeStore + "; nothing left stopbard"}}
	if err := e.record(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Void(ctx, requestID, rec) }); err != nil {
		e.cfg.Logger.Error("abandon: could not void the reservation; it stays counted until it lapses or past its window",
			"severity", "high", "request_id", requestID, "err", err)
	}
	if e.cfg.Pending == nil {
		return
	}
	e.escMu.Lock()
	defer e.escMu.Unlock()
	pe, ok, err := e.cfg.Pending.Get(ctx, requestID)
	if err != nil || !ok || (pe.State != "" && pe.State != model.EscalationPending) {
		if err != nil {
			e.cfg.Logger.Error("abandon: could not read the escalation", "severity", "high", "request_id", requestID, "err", err)
		}
		return
	}
	now := e.cfg.Clock()
	d := e.deny(requestID, now, pe.payloadHash(), failed(CodeStore, errors.New("escalation recorded after the requester was answered FAIL_CLOSED_STORE")))
	if err := e.resolve(ctx, &pe, model.EscalationDenied, d, "", now, model.AuditDecision, map[string]any{"decision": d}); err != nil {
		e.unaudited(requestID, err)
	}
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
