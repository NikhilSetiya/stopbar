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
	"time"

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
type Limiter interface {
	Reserve(ctx context.Context, id string, req model.EnrichedRequest, ttl time.Duration) error
	Commit(ctx context.Context, id, txRef string) error
	Release(ctx context.Context, id string) error
}

// Domain errors a Limiter returns; anything else is FAIL_CLOSED_LIMITER.
// Commit and Release return ErrUnknownReservation or ErrReservationExpired
// for an ID with nothing to act on.
var (
	ErrCapExceeded        = errors.New("limiter: cap exceeded")
	ErrCircuitOpen        = errors.New("limiter: circuit breaker open")
	ErrUnknownReservation = errors.New("limiter: unknown reservation")
	ErrReservationExpired = errors.New("limiter: reservation expired")
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
	DefaultDecisionTTL  = 60 * time.Second
	DefaultStageTimeout = time.Second
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
	Clock        func() time.Time
	Logger       *slog.Logger
}

// Engine implements gateway.Evaluator.
type Engine struct{ cfg Config }

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

func failed(code string, err error) *stageError { return &stageError{code, err} }

// call runs fn with the stage timeout, converting a panic or a timeout into
// an error. A component that ignores ctx is abandoned on timeout; callers
// must not read state that fn may still be writing.
func (e *Engine) call(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.StageTimeout)
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
	return e.evaluate(ctx, req, now), nil
}

func (e *Engine) evaluate(ctx context.Context, req model.ActionRequest, now time.Time) model.Decision {
	audit := func(d model.Decision, extra map[string]any) model.Decision {
		body := map[string]any{"request": req, "decision": d}
		for k, v := range extra {
			body[k] = v
		}
		err := e.call(ctx, func(ctx context.Context) error { return e.cfg.Audit.Append(ctx, model.AuditDecision, body) })
		if err == nil {
			return d
		}
		e.cfg.Logger.Error("audit append failed", "request_id", req.ID, "outcome", d.Outcome, "err", err)
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
	if pr.Outcome != model.Allow {
		// Escalations do not reserve: approval (CS-151) re-runs the limiter,
		// so pending escalations cannot tie up caps.
		return audit(d, ctxRecord)
	}

	// limiter
	id := req.ID
	if err := e.call(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Reserve(ctx, id, er, e.cfg.DecisionTTL) }); err != nil {
		e.release(ctx, id) // a timed-out Reserve may still land
		return audit(e.denyWith(d, limiterFailure(err)), ctxRecord)
	}
	d.ReservationID = &id

	// sign
	var token string
	if err := e.call(ctx, func(ctx context.Context) (err error) { token, err = e.cfg.Signer.Sign(ctx, req, d); return }); err != nil || token == "" {
		if err == nil {
			err = errors.New("signer returned an empty token")
		}
		e.release(ctx, id)
		return audit(e.denyWith(d, failed(CodeSigner, err)), ctxRecord)
	}
	d.Token = token

	// audit: no unaudited allow. On failure the token is discarded.
	out := audit(d, ctxRecord)
	if out.Outcome != model.Allow {
		e.release(ctx, id)
	}
	return out
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
func (e *Engine) release(ctx context.Context, id string) {
	err := e.call(context.WithoutCancel(ctx), func(ctx context.Context) error { return e.cfg.Limiter.Release(ctx, id) })
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
	case CodeNormalize:
		if errors.Is(se.err, decision.ErrNoBinding) {
			return "action kind cannot be bound to a decision in v1"
		}
		return "action could not be normalised"
	default:
		return "component failure; failing closed"
	}
}

// Commit records that the allowed action was broadcast (CS-105 wires the
// endpoint). Errors are returned to the caller.
func (e *Engine) Commit(ctx context.Context, requestID, txRef string) error {
	if err := e.call(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Commit(ctx, requestID, txRef) }); err != nil {
		return failed(CodeLimiter, err)
	}
	if err := e.call(ctx, func(ctx context.Context) error {
		return e.cfg.Audit.Append(ctx, model.AuditCommit, map[string]any{"request_id": requestID, "tx_ref": txRef})
	}); err != nil {
		return failed(CodeAudit, err)
	}
	return nil
}

// Release abandons an allowed action and frees its reservation. The reason
// (e.g. "client", or why a signer adapter refused) is audited.
func (e *Engine) Release(ctx context.Context, requestID, reason string) error {
	if err := e.call(ctx, func(ctx context.Context) error { return e.cfg.Limiter.Release(ctx, requestID) }); err != nil {
		return failed(CodeLimiter, err)
	}
	if err := e.call(ctx, func(ctx context.Context) error {
		return e.cfg.Audit.Append(ctx, model.AuditRelease, map[string]any{"request_id": requestID, "reason": reason})
	}); err != nil {
		return failed(CodeAudit, err)
	}
	return nil
}
