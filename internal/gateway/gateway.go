// Package gateway is Stopbar's HTTP front door (LLD §4). It accepts an
// ActionRequest, rejects anything malformed with a typed error, and hands
// well-formed requests to an Evaluator. It never produces a decision itself:
// with no Evaluator configured, /v1/evaluate answers 503, so the gateway on
// its own can never yield an allow.
//
// Checks run in this order, cheapest and most hostile-input-first:
// method → content type → body size → JSON well-formedness (via RFC 8785,
// which also rejects duplicate members) → integer precision → exact-case keys
// → strict decode (unknown fields rejected) → model validation. Nonce/TTL (CS-102) and
// authentication (CS-103) slot in before evaluation.
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

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// MaxBodyBytes bounds a request body (LLD §4).
const MaxBodyBytes = 64 << 10

// maxSafeInt is 2^53: the largest magnitude at which every integer is exactly
// representable as an IEEE-754 double, which is what JCS hashes.
var maxSafeInt = new(big.Rat).SetInt64(1 << 53)

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
)

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
	Evaluator Evaluator // nil: /v1/evaluate answers ENGINE_UNAVAILABLE
	Logger    *slog.Logger
}

// Gateway is an http.Handler serving the Stopbar API.
type Gateway struct {
	eval    Evaluator
	log     *slog.Logger
	metrics *metrics
	mux     *http.ServeMux
}

// New returns a Gateway.
func New(cfg Config) *Gateway {
	g := &Gateway{eval: cfg.Evaluator, log: cfg.Logger, metrics: newMetrics(), mux: http.NewServeMux()}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	g.route("/v1/evaluate", http.MethodPost, g.evaluate)
	g.route("/healthz", http.MethodGet, g.healthz)
	g.route("/metrics", http.MethodGet, g.serveMetrics)
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
	if g.eval == nil {
		return withID(fail(CodeEngineUnavailable, "no policy engine configured"), req.ID)
	}
	d, err := g.eval.Evaluate(r.Context(), req)
	if err != nil {
		g.log.Error("evaluator error", "request_id", req.ID, "err", err)
		return withID(fail(CodeInternal, "evaluation failed"), req.ID)
	}
	// Never emit a decision that is malformed or about another request.
	if verr := d.Validate(); verr != nil || d.RequestID != req.ID {
		g.log.Error("evaluator returned invalid decision", "request_id", req.ID, "decision_request_id", d.RequestID, "err", verr)
		return withID(fail(CodeInternal, "evaluation failed"), req.ID)
	}
	status := http.StatusOK
	if d.Outcome == model.Escalate {
		status = http.StatusAccepted
	}
	g.metrics.decision(d.Outcome)
	return g.writeJSON(w, "/v1/evaluate", status, d)
}

func withID(e *apiError, id string) *apiError { e.RequestID = id; return e }

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

func (g *Gateway) serveMetrics(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	g.metrics.request("/metrics", http.StatusOK)
	if _, err := w.Write([]byte(g.metrics.render())); err != nil {
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
