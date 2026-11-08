// Package gateway is Stopbar's HTTP front door (LLD §4). It accepts an
// ActionRequest, rejects anything malformed with a typed error, and hands
// well-formed requests to an Evaluator. It never produces a decision itself:
// with no Evaluator configured, /v1/evaluate answers 503, so the gateway on
// its own can never yield an allow.
//
// Checks run in this order, cheapest and most hostile-input-first:
// method → content type → body size → JSON well-formedness (via RFC 8785,
// which also rejects duplicate members) → integer precision → exact-case keys
// → strict decode (unknown fields rejected) → model validation → freshness
// (issued_at within skew, not expired) → nonce consumed. The nonce is spent
// before evaluation, so even a denied request cannot be retried with it.
// Authentication (CS-103) slots in before the body is read.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
)

// MaxBodyBytes bounds a request body (LLD §4).
const MaxBodyBytes = 64 << 10

// maxSafeInt is 2^53: the largest magnitude at which every integer is exactly
// representable as an IEEE-754 double, which is what JCS hashes.
var maxSafeInt = new(big.Rat).SetInt64(1 << 53)

// EvalScope is the scope an API key needs to call /v1/evaluate.
const EvalScope = "evaluate"

// Authenticator derives the caller's identity from the request (an API key
// header now; mTLS/SPIFFE later). It returns auth.ErrUnauthenticated for a
// missing or unknown credential. nil means auth is off (dev loopback only).
type Authenticator interface {
	Authenticate(r *http.Request) (auth.Identity, error)
}

// AuditSink records a gateway-level rejection (an identity mismatch or a
// missing scope) in the hash-chained audit log.
type AuditSink interface {
	Append(ctx context.Context, t model.AuditRecordType, body any) error
}

// BearerAuthenticator authenticates "Authorization: Bearer <secret>" against a
// key store (CS-103).
type BearerAuthenticator struct{ Store *auth.KeyStore }

// Authenticate returns the identity the bearer token authenticates as.
func (b BearerAuthenticator) Authenticate(r *http.Request) (auth.Identity, error) {
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	return b.Store.Verify(strings.TrimSpace(secret))
}

// Evaluator is the engine as the gateway sees it (LLD §2 Engine.Evaluate).
type Evaluator interface {
	Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error)
}

// Code is a typed gateway error code, returned in the error body.
type Code string

const (
	CodeNotFound          Code = "NOT_FOUND"
	CodeMethodNotAllowed  Code = "METHOD_NOT_ALLOWED"
	CodeUnsupportedMedia  Code = "UNSUPPORTED_MEDIA_TYPE"
	CodeBodyTooLarge      Code = "BODY_TOO_LARGE"
	CodeMalformedJSON     Code = "MALFORMED_JSON"
	CodeDuplicateKey      Code = "DUPLICATE_KEY"
	CodeNumberPrecision   Code = "NUMBER_PRECISION"
	CodeUnknownField      Code = "UNKNOWN_FIELD"
	CodeInvalidRequest    Code = "INVALID_REQUEST"
	CodeEngineUnavailable Code = "ENGINE_UNAVAILABLE"
	CodeInternal          Code = "INTERNAL"
	CodeExpired           Code = "EXPIRED"
	CodeIssuedInFuture    Code = "ISSUED_IN_FUTURE"
	CodeNonceReplayed     Code = "NONCE_REPLAYED"
	CodeUnauthenticated   Code = "UNAUTHENTICATED"   // CS-103: missing or unknown credential
	CodeIdentityMismatch  Code = "IDENTITY_MISMATCH" // body tenant/agent != authenticated identity
	CodeForbiddenScope    Code = "FORBIDDEN_SCOPE"   // the key lacks the required scope
	CodeRateLimited       Code = "RATE_LIMITED"      // per-identity rate limit exceeded
)

// ClockSkew is how far issued_at may lead or trail the gateway clock (LLD §4).
const ClockSkew = 30 * time.Second

// NonceRetention is how long a consumed nonce is remembered: longer than any
// request carrying it could still pass the freshness check.
const NonceRetention = model.MaxTTL + 2*ClockSkew

// NonceStore is an atomic check-and-set of single-use nonces (internal/nonce).
// The accepted request's audit entry is written in the same transaction as
// the consumed nonce.
type NonceStore interface {
	ConsumeWith(key string, until time.Time, entry *model.AuditEntry) (fresh bool, err error)
}

var codeStatus = map[Code]int{
	CodeNotFound:          http.StatusNotFound,
	CodeMethodNotAllowed:  http.StatusMethodNotAllowed,
	CodeUnsupportedMedia:  http.StatusUnsupportedMediaType,
	CodeBodyTooLarge:      http.StatusRequestEntityTooLarge,
	CodeMalformedJSON:     http.StatusBadRequest,
	CodeDuplicateKey:      http.StatusBadRequest,
	CodeNumberPrecision:   http.StatusBadRequest,
	CodeUnknownField:      http.StatusBadRequest,
	CodeInvalidRequest:    http.StatusBadRequest,
	CodeEngineUnavailable: http.StatusServiceUnavailable,
	CodeInternal:          http.StatusInternalServerError,
	CodeExpired:           http.StatusBadRequest,
	CodeIssuedInFuture:    http.StatusBadRequest,
	CodeNonceReplayed:     http.StatusBadRequest,
	CodeUnauthenticated:   http.StatusUnauthorized,
	CodeIdentityMismatch:  http.StatusForbidden,
	CodeForbiddenScope:    http.StatusForbidden,
	CodeRateLimited:       http.StatusTooManyRequests,
}

// ErrorBody is the wire shape of every non-2xx response (LLD §4.1).
type ErrorBody struct {
	Code      Code     `json:"code"`
	Message   string   `json:"message"`
	RequestID string   `json:"request_id,omitempty"`
	Problems  []string `json:"problems,omitempty"`
}

type apiError struct {
	ErrorBody
}

func (e *apiError) Error() string { return string(e.Code) + ": " + e.Message }

func fail(c Code, format string, a ...any) *apiError {
	return &apiError{ErrorBody{Code: c, Message: fmt.Sprintf(format, a...)}}
}

// Config wires a Gateway.
type Config struct {
	Evaluator Evaluator  // nil: /v1/evaluate answers ENGINE_UNAVAILABLE
	Nonces    NonceStore // nil: an in-memory store (replays reopen on restart)
	// Keys lists the decision-token keys (active and retired) for /v1/keys.
	Keys func() []decision.JWK
	// Counters adds components' counters (e.g. the engine's
	// stopbar_audit_unavailable_denials_total) to /metrics.
	Counters func() map[string]uint64
	Logger   *slog.Logger
	// Clock is for tests. stopbard never sets it: a configurable clock would
	// be a switch that turns freshness checks off.
	Clock func() time.Time
	// Authenticator derives the caller identity (CS-103). nil: auth is off, and
	// stopbard then refuses any non-loopback listen address.
	Authenticator Authenticator
	// Audit records gateway-level rejections (identity mismatch, missing scope).
	Audit AuditSink
	// RatePerMin is the per-identity request cap per minute (0: no gateway cap).
	RatePerMin int
}

// Gateway is an http.Handler serving the Stopbar API.
type Gateway struct {
	eval    Evaluator
	nonces  NonceStore
	keys    func() []decision.JWK
	extra   func() map[string]uint64
	clock   func() time.Time
	log     *slog.Logger
	metrics *metrics
	mux     *http.ServeMux
	auth    Authenticator
	audit   AuditSink
	rate    *rateLimiter
}

// New returns a Gateway.
func New(cfg Config) *Gateway {
	g := &Gateway{eval: cfg.Evaluator, nonces: cfg.Nonces, keys: cfg.Keys, extra: cfg.Counters, clock: cfg.Clock, log: cfg.Logger, metrics: newMetrics(), mux: http.NewServeMux(),
		auth: cfg.Authenticator, audit: cfg.Audit, rate: newRateLimiter(cfg.RatePerMin)}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	if g.clock == nil {
		g.clock = time.Now
	}
	if g.nonces == nil {
		g.nonces = nonce.NewMemory(g.clock)
	}
	g.route("/v1/evaluate", http.MethodPost, g.evaluate)
	g.route("/healthz", http.MethodGet, g.healthz)
	g.route("/metrics", http.MethodGet, g.serveMetrics)
	g.route("/v1/keys", http.MethodGet, g.serveKeys)
	g.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g.writeError(w, "other", fail(CodeNotFound, "no route for %s", r.URL.Path))
	})
	return g
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

// route registers path for one method, answering anything else with a typed
// 405 (ServeMux's own 405 is plain text).
func (g *Gateway) route(path, method string, h func(http.ResponseWriter, *http.Request) error) {
	g.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			g.writeError(w, path, fail(CodeMethodNotAllowed, "%s requires %s", path, method))
			return
		}
		defer func() {
			if p := recover(); p != nil {
				g.log.Error("panic in handler", "path", path, "panic", p, "stack", string(debug.Stack()))
				g.writeError(w, path, fail(CodeInternal, "internal error"))
			}
		}()
		if err := h(w, r); err != nil {
			var ae *apiError
			if !errors.As(err, &ae) {
				g.log.Error("handler error", "path", path, "err", err)
				ae = fail(CodeInternal, "internal error")
			}
			g.writeError(w, path, ae)
		}
	})
}

func (g *Gateway) evaluate(w http.ResponseWriter, r *http.Request) error {
	req, err := decodeActionRequest(w, r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if g.auth != nil { // CS-103: identity comes from auth, never the body
		id, aerr := g.auth.Authenticate(r)
		if aerr != nil {
			return withID(fail(CodeUnauthenticated, "missing or invalid credential"), req.ID)
		}
		if !id.HasScope(EvalScope) {
			g.auditReject(ctx, id, req, "key lacks the "+EvalScope+" scope")
			return withID(fail(CodeForbiddenScope, "the API key lacks the %q scope", EvalScope), req.ID)
		}
		if req.Tenant != id.Tenant || (req.Actor.AgentID != "" && req.Actor.AgentID != id.AgentID) {
			g.auditReject(ctx, id, req, "body tenant/agent does not match the authenticated identity")
			return withID(fail(CodeIdentityMismatch, "request tenant/agent does not match the authenticated identity"), req.ID)
		}
		if !g.rate.allow(id.KeyID, g.clock()) {
			return withID(fail(CodeRateLimited, "per-identity rate limit exceeded"), req.ID)
		}
		ctx = auth.WithIdentity(ctx, id)
	}
	if err := g.checkFresh(req); err != nil {
		return err
	}
	if g.eval == nil {
		return withID(fail(CodeEngineUnavailable, "no policy engine configured"), req.ID)
	}
	d, err := g.eval.Evaluate(ctx, req)
	if err != nil {
		g.log.Error("evaluator error", "request_id", req.ID, "err", err)
		return withID(fail(CodeInternal, "evaluation failed"), req.ID)
	}
	// Never emit a decision that is malformed or about another request.
	if verr := d.Validate(); verr != nil || d.RequestID != req.ID {
		g.log.Error("evaluator returned invalid decision", "request_id", req.ID, "decision_request_id", d.RequestID, "err", verr)
		return withID(fail(CodeInternal, "evaluation failed"), req.ID)
	}
	g.metrics.decision(d.Outcome)
	return g.writeJSON(w, "/v1/evaluate", outcomeStatus[d.Outcome], d)
}

// outcomeStatus makes the status code alone safe to act on: a client that
// checks only "2xx" can never read a deny as an allow. 200 means allow and
// nothing else. The decision is in the body for every outcome.
var outcomeStatus = map[model.Outcome]int{
	model.Allow:    http.StatusOK,
	model.Escalate: http.StatusAccepted,
	model.Deny:     http.StatusForbidden,
}

func withID(e *apiError, id string) *apiError { e.RequestID = id; return e }

// auditReject records a gateway-level rejection in the audit log. The
// authenticated identity goes INSIDE the body, so audit-hash v1 is unchanged.
func (g *Gateway) auditReject(ctx context.Context, id auth.Identity, req model.ActionRequest, reason string) {
	if g.audit == nil {
		return
	}
	body := map[string]any{"request_id": req.ID, "tenant": req.Tenant, "actor": req.Actor,
		"identity": id, "reason": reason}
	if err := g.audit.Append(ctx, model.AuditAuthReject, body); err != nil {
		g.log.Error("audit of auth rejection failed", "request_id", req.ID, "err", err)
	}
}

// checkFresh enforces the time window (both directions) and spends the
// nonce. It runs before evaluation, so the nonce is consumed whatever the
// engine decides.
func (g *Gateway) checkFresh(req model.ActionRequest) error {
	now := g.clock()
	switch {
	case req.IssuedAt.After(now.Add(ClockSkew)):
		return withID(fail(CodeIssuedInFuture, "issued_at is more than %s ahead of the gateway clock", ClockSkew), req.ID)
	case !now.Before(req.IssuedAt.Add(time.Duration(req.TTLSeconds)*time.Second + ClockSkew)):
		return withID(fail(CodeExpired, "request expired (issued_at + ttl_seconds + %s skew has passed)", ClockSkew), req.ID)
	}
	fresh, err := g.nonces.ConsumeWith(nonce.Key(req.Tenant, req.Actor.AgentID, req.Nonce), now.Add(NonceRetention),
		&model.AuditEntry{Type: model.AuditRequest, Body: req})
	if err != nil {
		g.log.Error("nonce store failed; failing closed", "request_id", req.ID, "err", err)
		return withID(fail(CodeInternal, "replay protection unavailable"), req.ID)
	}
	if !fresh {
		return withID(fail(CodeNonceReplayed, "nonce already used by this tenant and agent"), req.ID)
	}
	return nil
}

// decodeActionRequest applies every structural check, in order.
func decodeActionRequest(w http.ResponseWriter, r *http.Request) (model.ActionRequest, error) {
	var req model.ActionRequest
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return req, fail(CodeUnsupportedMedia, "Content-Type must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return req, fail(CodeBodyTooLarge, "body exceeds %d bytes", MaxBodyBytes)
		}
		return req, fail(CodeMalformedJSON, "reading body: %v", err)
	}
	if _, err := canon.Transform(body); err != nil {
		if errors.Is(err, canon.ErrDuplicateKey) {
			return req, fail(CodeDuplicateKey, "%v", err)
		}
		return req, fail(CodeMalformedJSON, "%v", err)
	}
	if err := checkIntegerPrecision(body); err != nil {
		return req, err
	}
	if err := checkExactKeys(body); err != nil {
		return req, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return req, fail(CodeUnknownField, "%s", strings.TrimPrefix(err.Error(), "json: "))
		}
		return req, fail(CodeInvalidRequest, "%s", strings.TrimPrefix(err.Error(), "json: "))
	}
	if err := req.Validate(); err != nil {
		e := fail(CodeInvalidRequest, "request failed validation")
		var ve *model.ValidationError
		if errors.As(err, &ve) {
			e.Problems = ve.Problems
		} else {
			e.Message = err.Error()
		}
		return req, withID(e, req.ID)
	}
	return req, nil
}

// checkIntegerPrecision rejects any integer-valued number whose magnitude
// exceeds 2^53. Such values change when hashed as JCS doubles, so the hash
// would bind something other than what was sent (decision-token-v1 §2.2).
// Large integers must travel as decimal strings.
func checkIntegerPrecision(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fail(CodeMalformedJSON, "%v", err) // unreachable after canon.Transform
		}
		n, ok := tok.(json.Number)
		if !ok {
			continue
		}
		v, ok := new(big.Rat).SetString(string(n))
		if !ok {
			return fail(CodeMalformedJSON, "invalid number %q", n)
		}
		if v.IsInt() && new(big.Rat).Abs(v).Cmp(maxSafeInt) > 0 {
			return fail(CodeNumberPrecision, "integer %s exceeds ±2^53; send it as a decimal string", n)
		}
	}
}

func (g *Gateway) healthz(w http.ResponseWriter, _ *http.Request) error {
	return g.writeJSON(w, "/healthz", http.StatusOK, map[string]string{"status": "ok"})
}

// serveKeys publishes the decision keys so verifiers can pin them out of
// band. Retired keys are listed: they still verify, never sign.
func (g *Gateway) serveKeys(w http.ResponseWriter, _ *http.Request) error {
	keys := []decision.JWK{}
	if g.keys != nil {
		keys = g.keys()
	}
	return g.writeJSON(w, "/v1/keys", http.StatusOK, map[string]any{"keys": keys})
}

func (g *Gateway) serveMetrics(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	g.metrics.request("/metrics", http.StatusOK)
	out := g.metrics.render()
	if g.extra != nil {
		out += renderCounters(g.extra())
	}
	if _, err := w.Write([]byte(out)); err != nil {
		g.log.Debug("write metrics", "err", err)
	}
	return nil
}

func (g *Gateway) writeError(w http.ResponseWriter, route string, e *apiError) {
	g.metrics.rejection(e.Code)
	status, ok := codeStatus[e.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	_ = g.writeJSON(w, route, status, e.ErrorBody)
}

func (g *Gateway) writeJSON(w http.ResponseWriter, route string, status int, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	g.metrics.request(route, status)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(append(b, '\n')); err != nil {
		g.log.Debug("write response", "route", route, "err", err) // client went away; headers are sent
	}
	return nil
}
