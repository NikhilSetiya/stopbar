package policy

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// CodeDefaultDeny marks a deny because no permit policy matched.
const CodeDefaultDeny = "DEFAULT_DENY"

// Evaluate implements engine.Policy. A returned error means the engine fails
// closed with FAIL_CLOSED_POLICY.
func (b *Bundle) Evaluate(_ context.Context, er model.EnrichedRequest) (engine.PolicyResult, error) {
	req, entities, err := b.cedarRequest(er)
	if err != nil {
		return engine.PolicyResult{}, err
	}
	// Reject a context that does not match the schema before evaluating:
	// a missing or ill-typed attribute must never reach Authorize.
	if err := b.validator.Request(req); err != nil {
		return engine.PolicyResult{}, fmt.Errorf("policy: request does not match schema: %w", err)
	}

	d, diag := cedar.Authorize(b.main, entities, req)
	if err := diagErr(diag); err != nil {
		return engine.PolicyResult{}, err
	}
	if d == cedar.Deny {
		reasons := b.reasons(diag)
		if len(reasons) == 0 {
			reasons = []model.Reason{{Code: CodeDefaultDeny, Message: "no permit policy matched"}}
		}
		return engine.PolicyResult{Outcome: model.Deny, Reasons: reasons, BundleHash: b.hash}, nil
	}
	// The escalate set holds only forbids, so any reason means one fired.
	_, ediag := cedar.Authorize(b.escalate, entities, req)
	if err := diagErr(ediag); err != nil {
		return engine.PolicyResult{}, err
	}
	if reasons := b.reasons(ediag); len(reasons) > 0 {
		return engine.PolicyResult{Outcome: model.Escalate, Reasons: reasons, BundleHash: b.hash}, nil
	}
	return engine.PolicyResult{Outcome: model.Allow, Reasons: []model.Reason{}, BundleHash: b.hash}, nil
}

// diagErr fails closed on any evaluation error (ADR 0001 finding 1).
func diagErr(d cedar.Diagnostic) error {
	if len(d.Errors) == 0 {
		return nil
	}
	msgs := make([]string, len(d.Errors))
	for i, e := range d.Errors {
		msgs[i] = fmt.Sprintf("%s: %s", e.PolicyID, e.Message)
	}
	sort.Strings(msgs)
	return fmt.Errorf("policy: evaluation error: %s", strings.Join(msgs, "; "))
}

func (b *Bundle) reasons(d cedar.Diagnostic) []model.Reason {
	out := make([]model.Reason, 0, len(d.Reasons))
	for _, r := range d.Reasons {
		msg, ok := b.messages[r.PolicyID]
		if !ok {
			msg = "policy " + string(r.PolicyID) + " matched"
		}
		out = append(out, model.Reason{Code: engine.CodePolicy, PolicyID: string(r.PolicyID), Message: msg})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })
	return out
}

// evmActions are the Cedar actions a decoded evm_tx may map to.
var evmActions = map[string]bool{"transfer": true, "approve": true, "contract_call": true}

// cedarRequest maps the enriched request onto the schema in
// examples/policies/stopbar.cedarschema. Anything it cannot represent
// faithfully is an error, never a default.
func (b *Bundle) cedarRequest(er model.EnrichedRequest) (cedar.Request, cedar.EntityMap, error) {
	a := er.Request.Action
	if a.Kind == model.KindToolCall {
		return b.toolCallRequest(er)
	}
	if a.Kind != model.KindEVMTx {
		return cedar.Request{}, nil, fmt.Errorf("policy: no policy context for action kind %q", a.Kind)
	}
	if !evmActions[er.Intent.Kind] {
		return cedar.Request{}, nil, fmt.Errorf("policy: decoded intent %q is not a policy action", er.Intent.Kind)
	}
	var problems []string
	dec := func(name string, s *string) cedar.Value {
		if s == nil {
			problems = append(problems, name+" is missing")
			return nil
		}
		d, err := toCedarDecimal(*s)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			return nil
		}
		return d
	}
	vel := func(window string) model.Velocity {
		v, ok := er.Velocity[window]
		if !ok {
			problems = append(problems, "velocity "+window+" is missing")
		}
		return v
	}
	v1h, v24h := vel("1h"), vel("24h")
	ctx := cedar.RecordMap{
		"price_stale":           cedar.Boolean(er.PriceStale),
		"taint":                 stringSet(er.Taint),
		"flags":                 stringSet(er.Intent.Flags),
		"dest_known":            cedar.Boolean(er.Destination.Known),
		"dest_similar_to_known": cedar.Boolean(er.Destination.SimilarToKnown),
		"vel_1h_usd":            dec("velocity 1h usd", &v1h.USD),
		"vel_24h_usd":           dec("velocity 24h usd", &v24h.USD),
		"vel_1h_count":          cedar.Long(v1h.Count),
	}
	// amount_usd and pct_of_balance are optional (CS-131, LLD §3.3): a stale or
	// unavailable price leaves them absent, so a policy that reads one must
	// guard with `context has …`, and a missing price reaches a stale-price
	// escalate policy rather than failing closed. (No policy needs amount_usd to
	// deny an unlimited approval — that rides on the decoder's flag.)
	if er.AmountUSD != nil {
		ctx["amount_usd"] = dec("amount_usd", er.AmountUSD)
	}
	if er.PctOfBalance != nil {
		ctx["pct_of_balance"] = dec("pct_of_balance", er.PctOfBalance)
	}
	if er.MinutesSinceCodeChange != nil {
		ctx["minutes_since_code_change"] = cedar.Long(*er.MinutesSinceCodeChange)
	}
	if er.ApprovalUSD != nil {
		ctx["approval_usd"] = dec("approval_usd", er.ApprovalUSD)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return cedar.Request{}, nil, errors.New("policy: incomplete context: " + strings.Join(problems, "; "))
	}

	principal := cedar.NewEntityUID("Stopbar::Agent", cedar.String(er.Request.Actor.AgentID))
	resource := cedar.NewEntityUID("Stopbar::Wallet", cedar.String(fmt.Sprintf("%d:%s", *a.ChainID, strings.ToLower(a.From))))
	entities := cedar.EntityMap{
		principal: {UID: principal, Attributes: cedar.NewRecord(cedar.RecordMap{"tenant": cedar.String(er.Request.Tenant)})},
		resource: {UID: resource, Attributes: cedar.NewRecord(cedar.RecordMap{
			"chain_id": cedar.Long(int64(*a.ChainID)), "address": cedar.String(strings.ToLower(a.From)),
		})},
	}
	return cedar.Request{
		Principal: principal,
		Action:    cedar.NewEntityUID("Stopbar::Action", cedar.String(er.Intent.Kind)),
		Resource:  resource,
		Context:   cedar.NewRecord(ctx),
	}, entities, nil
}

func stringSet(v []string) cedar.Set {
	vals := make([]cedar.Value, len(v))
	for i, s := range v {
		vals[i] = cedar.String(s)
	}
	return cedar.NewSet(vals...)
}

var reDecimal = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// toCedarDecimal converts a non-negative decimal string to a Cedar decimal,
// rounding UP to 4 fractional digits: amounts and shares only ever round
// toward the stricter policy outcome (ADR 0001 finding 4). Values beyond
// Cedar's range are an error, never clamped.
func toCedarDecimal(s string) (cedar.Decimal, error) {
	if !reDecimal.MatchString(s) {
		return cedar.Decimal{}, fmt.Errorf("%q is not a non-negative decimal string", s)
	}
	r, _ := new(big.Rat).SetString(s)
	scaled := new(big.Rat).Mul(r, big.NewRat(10000, 1))
	q, m := new(big.Int).QuoRem(scaled.Num(), scaled.Denom(), new(big.Int))
	if m.Sign() != 0 {
		q.Add(q, big.NewInt(1)) // ceiling (value is non-negative)
	}
	if !q.IsInt64() {
		return cedar.Decimal{}, fmt.Errorf("%q exceeds the Cedar decimal range", s)
	}
	v := q.Int64()
	return types.ParseDecimal(fmt.Sprintf("%d.%04d", v/10000, v%10000))
}

// toolCallRequest maps a tool call onto a tool-call bundle's schema:
// principal Agent, action "tool_call", resource Tool::<name>, and context
// facts derived only from the bundle's frozen trust map and the taint set.
// A bundle without a trust map, or a tool it doesn't declare, fails closed.
func (b *Bundle) toolCallRequest(er model.EnrichedRequest) (cedar.Request, cedar.EntityMap, error) {
	if b.trust == nil {
		return cedar.Request{}, nil, errors.New("policy: bundle has no tool trust map; tool calls fail closed")
	}
	tool := ""
	if er.Request.Action.Tool != nil {
		tool = *er.Request.Action.Tool
	}
	if !b.trust.known(tool) {
		return cedar.Request{}, nil, fmt.Errorf("policy: tool %q is not declared in %s; failing closed", tool, TrustFile)
	}
	principal := cedar.NewEntityUID("Stopbar::Agent", cedar.String(er.Request.Actor.AgentID))
	resource := cedar.NewEntityUID("Stopbar::Tool", cedar.String(tool))
	entities := cedar.EntityMap{
		principal: {UID: principal, Attributes: cedar.NewRecord(cedar.RecordMap{"tenant": cedar.String(er.Request.Tenant)})},
		resource:  {UID: resource, Attributes: cedar.NewRecord(cedar.RecordMap{})},
	}
	return cedar.Request{
		Principal: principal,
		Action:    cedar.NewEntityUID("Stopbar::Action", "tool_call"),
		Resource:  resource,
		Context: cedar.NewRecord(cedar.RecordMap{
			"state_changing":   cedar.Boolean(slices.Contains(b.trust.StateChangingTools, tool)),
			"account_identity": cedar.Boolean(slices.Contains(b.trust.AccountIdentityTools, tool)),
			"taint":            stringSet(er.Taint),
		}),
	}, entities, nil
}
