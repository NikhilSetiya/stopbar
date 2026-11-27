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
//
// The lifecycle routes act on an earlier request's state and always need an
// authenticated identity: commit/release (CS-105) take the requester's own
// evaluate-scoped key, approve/reject (CS-151) an approve-scoped key of the
// same tenant, and the decision poll (CS-152) either.
package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"mime"
	"net/http"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// MaxBodyBytes bounds a request body (LLD §4).
const MaxBodyBytes = 64 << 10

// maxSafeInt is 2^53: the largest magnitude at which every integer is exactly
// representable as an IEEE-754 double, which is what JCS hashes.
var maxSafeInt = new(big.Rat).SetInt64(1 << 53)

// EvalScope is the scope an API key needs to call /v1/evaluate (and to commit
// or release its own reservations, CS-105). ContactsScope is the scope to
// request, remove or list destination registry entries (CS-134). ApproveScope
// is kept only as a legacy scope name some deployments may still issue;
// CS-151 moved every approval (escalations, breaker resets, contact
// additions) to Ed25519 signatures (spec/approval-signature-v1.md) verified
// against configured approver keys, so no API key scope grants approval
// authority.
const (
	EvalScope     = "evaluate"
	ApproveScope  = "approve"
	ContactsScope = "contacts"
)

// Contacts is the destination registry as the gateway sees it (CS-134,
// enrich.Registry). Tenant and identity always come from the credential.
type Contacts interface {
	Request(tenant, addr, label string, by auth.Identity, now time.Time) (model.Contact, error)
	Approve(tenant, id string, sig approval.SignedContact, by auth.Identity, now time.Time) (model.Contact, error)
	Remove(tenant, addr string, by auth.Identity, now time.Time) (model.Contact, error)
	List(tenant string, now time.Time) ([]model.Contact, error)
}

// Approver drives the escalation lifecycle (CS-151/152): Approve verifies a
// signed envelope and adds its vote, re-evaluating and, on quorum, executing
// the escalation if it now allows; Reject verifies a signed reject envelope,
// which denies outright on quorum of one; Status reports the escalation.
// They return model.ErrNoPending for an id the caller cannot see,
// approval.ErrDuplicateVote for a second vote from an owner who already
// holds one, and model.ErrResolved once it is allowed, denied or expired. A
// signature that fails verification is not a Go error: it comes back as a
// deny Decision with the VerifyError's code as the reason (CS-151).
type Approver interface {
	Approve(ctx context.Context, id string, sig approval.SignedEscalation) (model.Decision, error)
	Reject(ctx context.Context, id string, sig approval.SignedEscalation) (model.Decision, error)
	Status(ctx context.Context, id string) (model.EscalationStatus, error)
	// PolicyBundleHash is the active policy bundle's hash, which an
	// escalation approval signs (spec/approval-signature-v1.md §2).
	PolicyBundleHash() string
}

// Actions settles an allowed request's reservation (CS-105, Engine.Commit and
// Release). Owner reports who it was reserved for, so only that requester can
// settle it. Commit and Release return model.ErrUnknownReservation,
// ErrReservationExpired or ErrAlreadyCommitted for an id with nothing to act on.
type Actions interface {
	Owner(id string) (tenant, agent string, ok bool)
	Commit(ctx context.Context, id, txRef string) error
	Release(ctx context.Context, id, reason string) error
}

// Breaker is the tenant circuit breaker as the gateway sees it (CS-124, the
// limiter). ResetBreaker verifies a signed breaker-reset envelope
// (spec/approval-signature-v1.md §3) against the configured approver keys
// and the open trip, records its vote, and returns the status after it; it
// returns model.ErrBreakerNotOpen for a closed breaker, model.ErrDuplicateVote
// for a second vote from an owner who already holds one, and
// *approval.VerifyError for a signature that does not verify.
type Breaker interface {
	BreakerStatus(tenant string) model.BreakerStatus
	ResetBreaker(ctx context.Context, tenant string, sig approval.SignedBreakerReset) (model.BreakerStatus, error)
}

// Authenticator derives the caller's identity from the request (an API key
// header, or an mTLS client certificate's SPIFFE ID). It returns auth.ErrUnauthenticated for a
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

// MTLSAuthenticator authenticates the TLS client certificate (CS-103
// increment 3, ADR 0006): its single SPIFFE ID URI SAN, mapped to an identity
// by operator configuration. No certificate, or one that does not verify or
// is unmapped, is unauthenticated (401).
type MTLSAuthenticator struct{ Map *auth.CertMap }

// Authenticate returns the identity the peer certificate authenticates as.
func (m MTLSAuthenticator) Authenticate(r *http.Request) (auth.Identity, error) {
	if r.TLS == nil {
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	return m.Map.Identify(r.TLS.PeerCertificates, time.Now())
}

// ServerTLSConfig is the listener side of mTLS: TLS 1.3 only, and any client
// certificate presented must chain to clientCAs (else the handshake fails).
// A client with no certificate still completes the handshake so /healthz and
// /metrics stay reachable; every authenticated route then answers it 401.
func ServerTLSConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
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
	CodeConflict          Code = "CONFLICT"          // the reservation is already committed (CS-105)
	CodeAlreadyResolved   Code = "ALREADY_RESOLVED"  // the escalation was already allowed, denied or expired (CS-152)
	CodeReservationGone   Code = "RESERVATION_EXPIRED"
	CodeDuplicateVote     Code = "DUPLICATE_VOTE" // CS-151: this owner already holds a live vote
	CodeSelfApproval      Code = "SELF_APPROVAL"  // CS-134: the requester tried to approve their own contact addition
	// CodeInvalidSignature is a breaker-reset or contact-approval envelope
	// that failed Ed25519 verification (CS-151, spec/approval-signature-v1.md
	// §4/§8). Escalation approve/reject map a failed signature to a deny
	// Decision instead (the engine's own reason codes), since those routes
	// always have a decision to answer with.
	CodeInvalidSignature Code = "INVALID_SIGNATURE"
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
	ConsumeWith(ctx context.Context, key string, until time.Time, entry *model.AuditEntry) (fresh bool, err error)
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
	CodeConflict:          http.StatusConflict,
	CodeAlreadyResolved:   http.StatusConflict,
	CodeReservationGone:   http.StatusGone,
	CodeDuplicateVote:     http.StatusConflict,
	CodeInvalidSignature:  http.StatusBadRequest,
	CodeSelfApproval:      http.StatusForbidden,
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
	// Approver drives escalations (CS-151/152); nil disables /v1/approvals and
	// /v1/decisions.
	Approver Approver
	// Actions settles reservations (CS-105); nil disables /v1/actions.
	Actions Actions
	// Breaker serves /v1/breakers (CS-124); nil disables it.
	Breaker Breaker
	// Contacts serves /v1/contacts (CS-134); nil (or auth off) disables it.
	Contacts Contacts
	// State is the state file. When set, each evaluation's writes (nonce,
	// reservation, records, spent token, commit) join one store.Unit and are
	// committed in one transaction before the answer is written (CS-197).
	// nil: each component writes on its own.
	State *store.DB
}

// Gateway is an http.Handler serving the Stopbar API.
type Gateway struct {
	eval     Evaluator
	nonces   NonceStore
	state    *store.DB
	keys     func() []decision.JWK
	extra    func() map[string]uint64
	clock    func() time.Time
	log      *slog.Logger
	metrics  *metrics
	mux      *http.ServeMux
	auth     Authenticator
	audit    AuditSink
	rate     *rateLimiter
	approver Approver
	actions  Actions
	breaker  Breaker
	contacts Contacts
	routes   map[string]map[string]func(http.ResponseWriter, *http.Request) error
}

// New returns a Gateway.
func New(cfg Config) *Gateway {
	g := &Gateway{eval: cfg.Evaluator, nonces: cfg.Nonces, state: cfg.State, keys: cfg.Keys, extra: cfg.Counters, clock: cfg.Clock, log: cfg.Logger, metrics: newMetrics(), mux: http.NewServeMux(),
		auth: cfg.Authenticator, audit: cfg.Audit, rate: newRateLimiter(cfg.RatePerMin), approver: cfg.Approver, actions: cfg.Actions, breaker: cfg.Breaker,
		contacts: cfg.Contacts, routes: map[string]map[string]func(http.ResponseWriter, *http.Request) error{}}
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
	g.route("/v1/approvals/{id}", http.MethodPost, g.approve)
	g.routeMethod("GET /v1/approvals/{id}", g.approvalToSign)
	g.route("/v1/approvals/{id}/reject", http.MethodPost, g.reject)
	g.route("/v1/decisions/{id}", http.MethodGet, g.poll)
	g.route("/v1/actions/{id}/commit", http.MethodPost, g.commit)
	g.route("/v1/actions/{id}/release", http.MethodPost, g.release)
	g.route("/v1/breakers/{tenant}", http.MethodGet, g.breakerStatus)
	g.route("/v1/breakers/{tenant}/reset", http.MethodPost, g.breakerReset)
	g.route("/v1/contacts", http.MethodGet, g.listContacts)
	g.route("/v1/contacts", http.MethodPost, g.requestContact)
	g.route("/v1/contacts/{id}/approve", http.MethodPost, g.approveContact)
	g.route("/v1/contacts/{address}", http.MethodDelete, g.removeContact)
	g.route("/healthz", http.MethodGet, g.healthz)
	g.route("/metrics", http.MethodGet, g.serveMetrics)
	g.route("/v1/keys", http.MethodGet, g.serveKeys)
	g.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g.writeError(w, "other", fail(CodeNotFound, "no route for %s", r.URL.Path))
	})
	return g
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

// route registers h for method on path; a path may take several methods.
// Any other method gets a typed 405 (ServeMux's own 405 is plain text).
func (g *Gateway) route(path, method string, h func(http.ResponseWriter, *http.Request) error) {
	ms, seen := g.routes[path]
	if !seen {
		ms = map[string]func(http.ResponseWriter, *http.Request) error{}
		g.routes[path] = ms
	}
	ms[method] = h
	if seen {
		return
	}
	g.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h, ok := ms[r.Method]
		if !ok {
			allow := slices.Sorted(maps.Keys(ms))
			w.Header().Set("Allow", strings.Join(allow, ", "))
			g.writeError(w, path, fail(CodeMethodNotAllowed, "%s requires %s", path, strings.Join(allow, " or ")))
			return
		}
		g.wrap(path, h)(w, r)
	})
}

// routeMethod registers h for pattern, a Go 1.22+ method-qualified mux
// pattern (e.g. "GET /v1/approvals/{id}") — used to add a method to a path
// that route already registered a *different* method's bare pattern for
// (ServeMux resolves the method-qualified pattern as more specific, so both
// coexist without conflict).
func (g *Gateway) routeMethod(pattern string, h func(http.ResponseWriter, *http.Request) error) {
	g.mux.HandleFunc(pattern, g.wrap(pattern, h))
}

// wrap adds panic recovery and typed-error writing around h, shared by route
// and routeMethod.
func (g *Gateway) wrap(path string, h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
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
			g.auditReject(ctx, id, req, "credential lacks the "+EvalScope+" scope")
			return withID(fail(CodeForbiddenScope, "the credential lacks the %q scope", EvalScope), req.ID)
		}
		// Under mTLS the certificate's SPIFFE ID is the workload identity, so a
		// body claiming another one is a mismatch too.
		if req.Tenant != id.Tenant || (req.Actor.AgentID != "" && req.Actor.AgentID != id.AgentID) ||
			(id.Method == auth.MethodMTLS && req.Actor.WorkloadIdentity != "" && req.Actor.WorkloadIdentity != id.KeyID) {
			g.auditReject(ctx, id, req, "body tenant/agent does not match the authenticated identity")
			return withID(fail(CodeIdentityMismatch, "request tenant/agent does not match the authenticated identity"), req.ID)
		}
		if !g.rate.allow(id.KeyID, g.clock()) {
			return withID(fail(CodeRateLimited, "per-identity rate limit exceeded"), req.ID)
		}
		ctx = auth.WithIdentity(ctx, id)
	}
	// One evaluation, one transaction (CS-197, ADR 0009): every write below
	// joins u, and nothing is answered until u is durable. If it cannot be
	// written, nothing of it is (nonce, reservation, records, spent token,
	// commit all roll back) and the caller gets a 500, never the decision.
	var u *store.Unit
	if g.state != nil {
		u = g.state.NewUnit()
		ctx = store.WithUnit(ctx, u)
		defer func() { _ = u.Commit() }() // an early return still settles what joined (failure paths, panics)
	}
	if err := g.checkFresh(ctx, req); err != nil {
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
	if u != nil {
		if err := u.Commit(); err != nil {
			g.metrics.unwritten()
			g.log.Error("state write failed; nothing of this evaluation was recorded, answering 500", "severity", "high",
				"request_id", req.ID, "outcome", d.Outcome, "err", err)
			return withID(fail(CodeInternal, "state unavailable"), req.ID)
		}
	}
	g.metrics.decision(d.Outcome)
	return g.writeJSON(w, "/v1/evaluate", outcomeStatus[d.Outcome], d)
}

// authorize authenticates a lifecycle call and checks that the key carries one
// of scopes. A missing scope is audited.
func (g *Gateway) authorize(r *http.Request, id string, scopes ...string) (auth.Identity, error) {
	identity, err := g.auth.Authenticate(r)
	if err != nil {
		return identity, withID(fail(CodeUnauthenticated, "missing or invalid credential"), id)
	}
	if !slices.ContainsFunc(scopes, identity.HasScope) {
		g.auditReject(r.Context(), identity, model.ActionRequest{ID: id}, "credential lacks the "+strings.Join(scopes, " or ")+" scope")
		return identity, withID(fail(CodeForbiddenScope, "the credential lacks the %s scope", strings.Join(scopes, " or ")), id)
	}
	return identity, nil
}

// authenticateOnly authenticates a lifecycle call with no scope requirement
// (CS-151): approval and breaker-reset authorization is the Ed25519
// signature in the body, not any API key scope, so an API key here only
// identifies the HTTP caller for audit and rate limiting. With auth off
// (loopback dev) it is a no-op and ctx is returned unchanged.
func (g *Gateway) authenticateOnly(r *http.Request, id string) (context.Context, error) {
	ctx := r.Context()
	if g.auth == nil {
		return ctx, nil
	}
	identity, err := g.auth.Authenticate(r)
	if err != nil {
		return ctx, withID(fail(CodeUnauthenticated, "missing or invalid credential"), id)
	}
	return auth.WithIdentity(ctx, identity), nil
}

const maxApprovalBytes = 4 << 10

// decodeSigned decodes a small, bounded JSON body into v: well-formed
// (duplicate keys rejected) and unknown fields rejected. Unlike
// decodeActionRequest, case-insensitive key matching is not a hazard here —
// VerifyEscalation/VerifyBreakerReset re-canonicalise the Go struct they
// decoded into, never the raw wire bytes, so there is nothing for a
// mismatched body to desynchronise from (contrast ActionRequest's
// payload_hash, which must bind the exact submitted body).
func decodeSigned(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) *apiError {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return fail(CodeBodyTooLarge, "body exceeds %d bytes", maxBytes)
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return fail(CodeUnsupportedMedia, "Content-Type must be application/json")
	}
	if _, err := canon.Transform(raw); err != nil {
		if errors.Is(err, canon.ErrDuplicateKey) {
			return fail(CodeDuplicateKey, "%v", err)
		}
		return fail(CodeMalformedJSON, "%v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(CodeInvalidRequest, "%s", strings.TrimPrefix(err.Error(), "json: "))
	}
	return nil
}

// approve verifies the posted signed envelope (spec/approval-signature-v1.md
// §2, decision "approve") and adds its vote; on quorum it re-evaluates and,
// if it now allows, executes the escalation (CS-151/152). The outcome
// status is the decision's own (200 allow+executed, 202 still escalated or
// pending, 403 denied).
func (g *Gateway) approve(w http.ResponseWriter, r *http.Request) error {
	return g.resolve(w, r, "/v1/approvals", Approver.Approve)
}

// reject verifies the posted signed envelope (decision "reject") and, being
// a valid vote, denies the escalation outright regardless of quorum
// (CS-151, LLD §9 step 4): 403 with the deny decision.
func (g *Gateway) reject(w http.ResponseWriter, r *http.Request) error {
	return g.resolve(w, r, "/v1/approvals/reject", Approver.Reject)
}

func (g *Gateway) resolve(w http.ResponseWriter, r *http.Request, route string,
	fn func(Approver, context.Context, string, approval.SignedEscalation) (model.Decision, error)) error {
	id := r.PathValue("id")
	if g.approver == nil {
		return withID(fail(CodeEngineUnavailable, "approvals are not configured"), id)
	}
	ctx, err := g.authenticateOnly(r, id)
	if err != nil {
		return err
	}
	var sig approval.SignedEscalation
	if aerr := decodeSigned(w, r, &sig, maxApprovalBytes); aerr != nil {
		return withID(aerr, id)
	}
	d, err := fn(g.approver, ctx, id, sig)
	switch {
	case errors.Is(err, model.ErrNoPending):
		return withID(fail(CodeNotFound, "no pending escalation for that id"), id)
	case errors.Is(err, model.ErrResolved):
		return withID(fail(CodeAlreadyResolved, "the escalation was already resolved; GET /v1/decisions/%s for the outcome", id), id)
	case errors.Is(err, approval.ErrDuplicateVote):
		return withID(fail(CodeDuplicateVote, "this owner already holds a live vote on this escalation; a second distinct owner must vote"), id)
	case err != nil:
		g.log.Error("approval error", "route", route, "id", id, "err", err)
		return withID(fail(CodeInternal, "approval failed"), id)
	}
	return g.writeJSON(w, route, outcomeStatus[d.Outcome], d)
}

// EscalationToSign is GET /v1/approvals/{id} (CS-151): everything a CLI
// needs to build and sign an escalation approve/reject envelope
// (spec/approval-signature-v1.md §2), without separately decoding
// GET /v1/decisions/{id}'s full EscalationStatus.
type EscalationToSign struct {
	EscalationID string `json:"escalation_id"`
	PayloadHash  string `json:"payload_hash"`
	// PolicyBundleHash is the active policy bundle (spec §2, v2): a vote
	// signed against it counts only while stopbard runs this bundle.
	PolicyBundleHash string `json:"policy_bundle_hash"`
	Tenant           string `json:"tenant"`
	// MaxExpiry is now (the gateway's clock) plus approval.MaxExpiryAhead:
	// the latest expiry a signature can carry and still verify if submitted
	// immediately.
	MaxExpiry int64 `json:"max_expiry"`
}

// approvalToSign serves GET /v1/approvals/{id}: the object a signature must
// cover, for a pending escalation only (an id that is not pending or does
// not exist both answer 404, exactly as poll does, so a caller cannot tell
// the two apart).
func (g *Gateway) approvalToSign(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if g.approver == nil {
		return withID(fail(CodeEngineUnavailable, "approvals are not configured"), id)
	}
	ctx, err := g.authenticateOnly(r, id)
	if err != nil {
		return err
	}
	st, err := g.approver.Status(ctx, id)
	switch {
	case errors.Is(err, model.ErrNoPending):
		return withID(fail(CodeNotFound, "no escalation for that id"), id)
	case err != nil:
		g.log.Error("approval-to-sign error", "id", id, "err", err)
		return withID(fail(CodeInternal, "could not load the escalation"), id)
	case st.State != model.EscalationPending || st.Decision == nil:
		return withID(fail(CodeNotFound, "no pending escalation for that id"), id)
	}
	return g.writeJSON(w, "/v1/approvals", http.StatusOK, EscalationToSign{
		EscalationID: id, PayloadHash: st.Decision.PayloadHash, PolicyBundleHash: g.approver.PolicyBundleHash(),
		Tenant: st.Request.Tenant, MaxExpiry: g.clock().Add(approval.MaxExpiryAhead).Unix(),
	})
}

// stateStatus keeps the poll's status code as safe to act on as /v1/evaluate:
// 200 only once the escalation is allowed, 202 while it waits, 403 otherwise.
var stateStatus = map[model.EscalationState]int{
	model.EscalationPending: http.StatusAccepted,
	model.EscalationAllowed: http.StatusOK,
	model.EscalationDenied:  http.StatusForbidden,
	model.EscalationExpired: http.StatusForbidden,
}

// poll serves GET /v1/decisions/{id} (CS-152): the escalation's state and
// decision, to the requester itself (evaluate scope, same tenant and agent)
// or to an approver of its tenant. Anyone else gets 404, as for an unknown id.
func (g *Gateway) poll(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if g.approver == nil || g.auth == nil {
		return withID(fail(CodeEngineUnavailable, "approvals are not configured"), id)
	}
	identity, err := g.authorize(r, id, EvalScope, ApproveScope)
	if err != nil {
		return err
	}
	st, err := g.approver.Status(auth.WithIdentity(r.Context(), identity), id)
	if errors.Is(err, model.ErrNoPending) || (err == nil && !identity.HasScope(ApproveScope) && st.Request.Actor.AgentID != identity.AgentID) {
		return withID(fail(CodeNotFound, "no escalation for that id"), id)
	}
	if err != nil {
		g.log.Error("decision poll error", "id", id, "err", err)
		return withID(fail(CodeInternal, "poll failed"), id)
	}
	status, ok := stateStatus[st.State]
	if !ok {
		status = http.StatusForbidden
	}
	return g.writeJSON(w, "/v1/decisions", status, st)
}

// SettleBody is the body of /v1/actions/{id}/commit (tx_ref required: the
// broadcast tx hash) and /release (reason optional; the body may be empty).
type SettleBody struct {
	TxRef  string `json:"tx_ref,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const maxSettleBytes = 4 << 10

// commit reports that an allowed action was broadcast, turning its
// reservation into committed spend (CS-105).
func (g *Gateway) commit(w http.ResponseWriter, r *http.Request) error { return g.settle(w, r, true) }

// release abandons an allowed action and frees its reservation (CS-105).
func (g *Gateway) release(w http.ResponseWriter, r *http.Request) error { return g.settle(w, r, false) }

// settle serves commit and release. Only the requester (the same tenant and
// agent, with an evaluate-scoped key) may settle its reservation: another
// agent releasing it would free capacity that a still-valid token can spend.
// Retries are safe: committing again with the same tx_ref and releasing again
// both answer 200.
func (g *Gateway) settle(w http.ResponseWriter, r *http.Request, commit bool) error {
	id := r.PathValue("id")
	route := "/v1/actions/release"
	if commit {
		route = "/v1/actions/commit"
	}
	if g.actions == nil || g.auth == nil {
		return withID(fail(CodeEngineUnavailable, "commit/release are not configured"), id)
	}
	identity, err := g.authorize(r, id, EvalScope)
	if err != nil {
		return err
	}
	body, aerr := decodeSettle(w, r, commit)
	if aerr != nil {
		return withID(aerr, id)
	}
	tenant, agent, ok := g.actions.Owner(id)
	if !ok || tenant != identity.Tenant || agent != identity.AgentID {
		if ok {
			g.auditReject(r.Context(), identity, model.ActionRequest{ID: id, Tenant: tenant, Actor: model.Actor{AgentID: agent}}, "not the requester of this reservation")
		}
		return withID(fail(CodeNotFound, "no reservation for that id"), id)
	}
	ctx := auth.WithIdentity(r.Context(), identity) // the settler is in the audit record
	out := map[string]any{"request_id": id}
	if commit {
		err = g.actions.Commit(ctx, id, body.TxRef)
		out["state"], out["tx_ref"] = "committed", body.TxRef
		if errors.Is(err, model.ErrReservationExpired) {
			err, out["late"] = nil, true // a late commit still records the spend (LLD §7.3a)
		}
	} else {
		reason := body.Reason
		if reason == "" {
			reason = "client"
		}
		err = g.actions.Release(ctx, id, reason)
		out["state"] = "released"
	}
	switch {
	case err == nil:
		return g.writeJSON(w, route, http.StatusOK, out)
	case errors.Is(err, model.ErrUnknownReservation):
		return withID(fail(CodeNotFound, "no live or committed reservation for that id"), id)
	case errors.Is(err, model.ErrAlreadyCommitted):
		return withID(fail(CodeConflict, "the reservation is already committed"), id)
	case errors.Is(err, model.ErrReservationExpired):
		return withID(fail(CodeReservationGone, "the reservation already lapsed; nothing is held"), id)
	}
	g.log.Error("settle error", "route", route, "id", id, "err", err)
	return withID(fail(CodeInternal, "could not record the %s", out["state"]), id)
}

// decodeSettle applies the same structural checks as /v1/evaluate to the small
// settle body: JSON content type, size, well-formed without duplicate keys,
// exact-case known fields only.
func decodeSettle(w http.ResponseWriter, r *http.Request, commit bool) (SettleBody, *apiError) {
	var b SettleBody
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSettleBytes))
	if err != nil {
		return b, fail(CodeBodyTooLarge, "body exceeds %d bytes", maxSettleBytes)
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			return b, fail(CodeUnsupportedMedia, "Content-Type must be application/json")
		}
		if _, err := canon.Transform(raw); err != nil {
			if errors.Is(err, canon.ErrDuplicateKey) {
				return b, fail(CodeDuplicateKey, "%v", err)
			}
			return b, fail(CodeMalformedJSON, "%v", err)
		}
		if err := checkExactKeysAs(raw, reflect.TypeOf(SettleBody{})); err != nil {
			var ae *apiError
			errors.As(err, &ae)
			return b, ae
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&b); err != nil {
			return b, fail(CodeInvalidRequest, "%s", strings.TrimPrefix(err.Error(), "json: "))
		}
	}
	var problems []string
	switch {
	case commit && b.TxRef == "":
		problems = append(problems, "tx_ref is required")
	case !commit && b.TxRef != "":
		problems = append(problems, "tx_ref is not accepted on release")
	case commit && b.Reason != "":
		problems = append(problems, "reason is not accepted on commit")
	}
	if len(b.TxRef) > 256 || len(b.Reason) > 256 {
		problems = append(problems, "tx_ref and reason are at most 256 bytes")
	}
	if len(problems) > 0 {
		e := fail(CodeInvalidRequest, "request failed validation")
		e.Problems = problems
		return b, e
	}
	return b, nil
}

// breakerStatus serves a tenant's circuit breaker (CS-124). Reading it needs
// no particular scope — with auth on, any authenticated key may read any
// tenant's status (CS-151 moved authorization for the lifecycle routes to
// signatures, not API key scopes); with auth off (loopback dev) anyone on
// the host may.
func (g *Gateway) breakerStatus(w http.ResponseWriter, r *http.Request) error {
	tenant := r.PathValue("tenant")
	if g.breaker == nil {
		return fail(CodeEngineUnavailable, "no circuit breaker configured")
	}
	if _, err := g.authenticateOnly(r, tenant); err != nil {
		return err
	}
	return g.writeJSON(w, "/v1/breakers", http.StatusOK, g.breaker.BreakerStatus(tenant))
}

// breakerReset verifies the posted signed breaker-reset envelope
// (spec/approval-signature-v1.md §3) against the configured approver keys
// and the tenant's open trip, and records its vote toward the quorum
// (CS-151, replacing #128's API-key vote mechanism entirely: no API key
// scope or tenant match is checked here, only the signature). 200 means the
// vote completed the quorum and the breaker is closed; 202 means the vote
// is recorded but the quorum is not met, so the breaker stays open.
func (g *Gateway) breakerReset(w http.ResponseWriter, r *http.Request) error {
	tenant := r.PathValue("tenant")
	if g.breaker == nil {
		return fail(CodeEngineUnavailable, "no circuit breaker configured")
	}
	ctx, err := g.authenticateOnly(r, tenant)
	if err != nil {
		return err
	}
	var sig approval.SignedBreakerReset
	if aerr := decodeSigned(w, r, &sig, maxApprovalBytes); aerr != nil {
		return aerr
	}
	st, err := g.breaker.ResetBreaker(ctx, tenant, sig)
	switch {
	case errors.Is(err, model.ErrBreakerNotOpen):
		return fail(CodeNotFound, "the circuit breaker for tenant %q is not open", tenant)
	case errors.Is(err, model.ErrDuplicateVote):
		return fail(CodeDuplicateVote, "this owner already holds a live reset vote on this trip; a second distinct owner must vote")
	case err != nil:
		var ve *approval.VerifyError
		if errors.As(err, &ve) {
			return fail(CodeInvalidSignature, "signature rejected: %s", ve.Code)
		}
		g.log.Error("breaker reset failed", "tenant", tenant, "err", err)
		return fail(CodeInternal, "breaker reset vote not recorded")
	}
	status := http.StatusOK
	if st.Open {
		status = http.StatusAccepted
	}
	return g.writeJSON(w, "/v1/breakers", status, st)
}

// contactsAuth is the guard every /v1/contacts route shares: the registry
// and authentication must both be on (a registry change is attributed to,
// and separated by, the authenticated key).
func (g *Gateway) contactsAuth(r *http.Request, id string, scopes ...string) (auth.Identity, error) {
	if g.contacts == nil || g.auth == nil {
		return auth.Identity{}, withID(fail(CodeEngineUnavailable, "the contacts API needs a destination registry and authentication"), id)
	}
	return g.authorize(r, id, scopes...)
}

// contactError maps registry errors to typed codes.
func contactError(err error, id string) error {
	switch {
	case errors.Is(err, model.ErrNoContact):
		return withID(fail(CodeNotFound, "%v", err), id)
	case errors.Is(err, model.ErrContactExists), errors.Is(err, model.ErrContactApproved):
		return withID(fail(CodeConflict, "%v", err), id)
	case errors.Is(err, model.ErrSelfApproval):
		return withID(fail(CodeSelfApproval, "%v", err), id)
	}
	return err
}

// requestContact records a pending addition (CS-134): 202, since it is not
// active until approved and cooled off.
func (g *Gateway) requestContact(w http.ResponseWriter, r *http.Request) error {
	identity, err := g.contactsAuth(r, "", ContactsScope)
	if err != nil {
		return err
	}
	var cr model.ContactRequest
	if err := decodeBody(w, r, &cr); err != nil {
		return err
	}
	if err := cr.Validate(); err != nil {
		return invalid(err)
	}
	c, err := g.contacts.Request(identity.Tenant, cr.Address, cr.Label, identity, g.clock())
	if err != nil {
		return contactError(err, "")
	}
	return g.writeJSON(w, "/v1/contacts", http.StatusAccepted, c)
}

// approveContact records a signed approval vote on a pending addition
// (CS-151, spec/approval-signature-v1.md §3a): the Ed25519 signature
// authorizes it, never an API key scope, so any authenticated key may carry
// it. 200 means the vote met the quorum (the entry is cooling off); 202 means
// it is recorded and more distinct owners must sign. A self-approval is
// audited.
func (g *Gateway) approveContact(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	identity, err := g.contactsAuth(r, id, EvalScope, ContactsScope, ApproveScope)
	if err != nil {
		return err
	}
	var sig approval.SignedContact
	if aerr := decodeSigned(w, r, &sig, maxApprovalBytes); aerr != nil {
		return withID(aerr, id)
	}
	c, err := g.contacts.Approve(identity.Tenant, id, sig, identity, g.clock())
	var ve *approval.VerifyError
	switch {
	case errors.Is(err, model.ErrSelfApproval):
		g.auditReject(r.Context(), identity, model.ActionRequest{ID: id, Tenant: identity.Tenant}, "contact self-approval")
	case errors.Is(err, model.ErrDuplicateVote):
		return withID(fail(CodeDuplicateVote, "this owner already holds a live vote on this addition; a second distinct owner must sign"), id)
	case errors.As(err, &ve):
		return withID(fail(CodeInvalidSignature, "signature rejected: %s", ve.Code), id)
	}
	if err != nil {
		return contactError(err, id)
	}
	status := http.StatusOK
	if c.ApprovedAt == nil {
		status = http.StatusAccepted
	}
	return g.writeJSON(w, "/v1/contacts/approve", status, c)
}

// removeContact removes an entry at once, whatever its status.
func (g *Gateway) removeContact(w http.ResponseWriter, r *http.Request) error {
	addr := r.PathValue("address")
	identity, err := g.contactsAuth(r, addr, ContactsScope)
	if err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(addr); err != nil {
		return withID(fail(CodeInvalidRequest, "%v", err), addr)
	}
	c, err := g.contacts.Remove(identity.Tenant, addr, identity, g.clock())
	if err != nil {
		return contactError(err, addr)
	}
	return g.writeJSON(w, "/v1/contacts/remove", http.StatusOK, c)
}

// listContacts lists the tenant's entries with their status now, including
// every look-alike match. Approvers need it to review pending additions, so
// either scope may list.
func (g *Gateway) listContacts(w http.ResponseWriter, r *http.Request) error {
	identity, err := g.contactsAuth(r, "", ContactsScope, ApproveScope)
	if err != nil {
		return err
	}
	cs, err := g.contacts.List(identity.Tenant, g.clock())
	if err != nil {
		return err
	}
	return g.writeJSON(w, "/v1/contacts", http.StatusOK, map[string]any{"contacts": cs})
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
func (g *Gateway) checkFresh(ctx context.Context, req model.ActionRequest) error {
	now := g.clock()
	switch {
	case req.IssuedAt.After(now.Add(ClockSkew)):
		return withID(fail(CodeIssuedInFuture, "issued_at is more than %s ahead of the gateway clock", ClockSkew), req.ID)
	case !now.Before(req.IssuedAt.Add(time.Duration(req.TTLSeconds)*time.Second + ClockSkew)):
		return withID(fail(CodeExpired, "request expired (issued_at + ttl_seconds + %s skew has passed)", ClockSkew), req.ID)
	}
	fresh, err := g.nonces.ConsumeWith(ctx, nonce.Key(req.Tenant, req.Actor.AgentID, req.Nonce), now.Add(NonceRetention),
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
	if err := decodeBody(w, r, &req); err != nil {
		return req, err
	}
	if err := req.Validate(); err != nil {
		return req, withID(invalid(err), req.ID)
	}
	return req, nil
}

// decodeBody applies every structural check to a JSON body, in order, and
// strictly decodes it into dst (a pointer to a model type). The caller
// validates the result.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return fail(CodeUnsupportedMedia, "Content-Type must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fail(CodeBodyTooLarge, "body exceeds %d bytes", MaxBodyBytes)
		}
		return fail(CodeMalformedJSON, "reading body: %v", err)
	}
	if _, err := canon.Transform(body); err != nil {
		if errors.Is(err, canon.ErrDuplicateKey) {
			return fail(CodeDuplicateKey, "%v", err)
		}
		return fail(CodeMalformedJSON, "%v", err)
	}
	if err := checkIntegerPrecision(body); err != nil {
		return err
	}
	if err := checkExactKeysAs(body, reflect.TypeOf(dst)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return fail(CodeUnknownField, "%s", strings.TrimPrefix(err.Error(), "json: "))
		}
		return fail(CodeInvalidRequest, "%s", strings.TrimPrefix(err.Error(), "json: "))
	}
	return nil
}

// invalid maps a model Validate error to INVALID_REQUEST with every problem.
func invalid(err error) *apiError {
	e := fail(CodeInvalidRequest, "request failed validation")
	var ve *model.ValidationError
	if errors.As(err, &ve) {
		e.Problems = ve.Problems
	} else {
		e.Message = err.Error()
	}
	return e
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
