// Package model defines Countersign's wire types (LLD §3). JSON shapes here are
// the contract; spec/schemas/*.schema.json mirror them for non-Go clients.
//
// Monetary and on-chain integer amounts are decimal strings, never JSON
// numbers: wei values exceed 2^53 and must not pass through float64.
package model

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// ActionKind enumerates what is being asked to be signed or executed.
type ActionKind string

const (
	KindEVMTx      ActionKind = "evm_tx"
	KindToolCall   ActionKind = "tool_call"
	KindWithdrawal ActionKind = "withdrawal"
)

// Outcome is the policy decision.
type Outcome string

const (
	Allow    Outcome = "allow"
	Deny     Outcome = "deny"
	Escalate Outcome = "escalate"
)

// MaxTTL bounds how long a request may remain valid (LLD §4).
const MaxTTL = 300 * time.Second

// ActionRequest is what a requester submits for evaluation (LLD §3.1).
type ActionRequest struct {
	ID              string     `json:"id"`
	Tenant          string     `json:"tenant"`
	Nonce           string     `json:"nonce"`
	IssuedAt        time.Time  `json:"issued_at"`
	TTLSeconds      int        `json:"ttl_seconds"`
	Actor           Actor      `json:"actor"`
	Action          Action     `json:"action"`
	Provenance      Provenance `json:"provenance"`
	ParentRequestID *string    `json:"parent_request_id"`
}

// Actor identifies who is asking, and on whose behalf.
type Actor struct {
	AgentID          string `json:"agent_id"`
	WorkloadIdentity string `json:"workload_identity,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	OnBehalfOf       string `json:"on_behalf_of,omitempty"`
}

// Action is the thing to be signed or executed.
type Action struct {
	Kind     ActionKind     `json:"kind"`
	ChainID  *uint64        `json:"chain_id,omitempty"`
	From     string         `json:"from,omitempty"`
	To       string         `json:"to,omitempty"`
	ValueWei string         `json:"value_wei,omitempty"`
	Data     string         `json:"data,omitempty"`
	Tool     *string        `json:"tool"`
	Args     map[string]any `json:"args"`
}

// Provenance carries taint: where the inputs that led to this action came from.
type Provenance struct {
	Labels  []string `json:"labels"`
	Sources []Source `json:"sources,omitempty"`
	SDK     *SDKInfo `json:"sdk,omitempty"`
}

// Source is one piece of content that influenced the action.
type Source struct {
	Label string `json:"label"`
	Ref   string `json:"ref"`
	Hash  string `json:"hash,omitempty"`
}

// SDKInfo identifies the client library that built the request.
type SDKInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// IntentSummary is the decoder's independent, human-readable rendering (LLD §3.2).
type IntentSummary struct {
	Kind        string   `json:"kind"`
	Asset       *Asset   `json:"asset,omitempty"`
	Amount      string   `json:"amount,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Flags       []string `json:"flags"`
	Human       string   `json:"human"`
	PayloadHash string   `json:"payload_hash"`
}

// Asset is a token on a chain.
type Asset struct {
	ChainID  uint64 `json:"chain_id"`
	Address  string `json:"address"`
	Symbol   string `json:"symbol"`
	Decimals int    `json:"decimals"`
}

// EnrichedRequest is the policy evaluation context (LLD §3.3).
// Decimal values are strings to avoid float rounding in policy comparisons.
type EnrichedRequest struct {
	Request                ActionRequest       `json:"request"`
	Intent                 IntentSummary       `json:"intent"`
	AmountUSD              *string             `json:"amount_usd"`
	PriceStale             bool                `json:"price_stale"`
	PctOfBalance           *string             `json:"pct_of_balance"`
	Velocity               map[string]Velocity `json:"velocity"` // keys: 1m, 1h, 24h
	Destination            DestinationInfo     `json:"destination"`
	Taint                  []string            `json:"taint"`
	MinutesSinceCodeChange *int                `json:"minutes_since_code_change"`
}

// Velocity is spend in a window.
type Velocity struct {
	USD   string `json:"usd"`
	Count int    `json:"count"`
}

// DestinationInfo is what we know about the recipient.
type DestinationInfo struct {
	Known          bool `json:"known"`
	SimilarToKnown bool `json:"similar_to_known"`
}

// Reason explains one policy contribution to a decision.
type Reason struct {
	PolicyID string `json:"policy_id"`
	Message  string `json:"message"`
}

// Decision is the engine's verdict (LLD §3.4).
type Decision struct {
	RequestID        string     `json:"request_id"`
	Outcome          Outcome    `json:"outcome"`
	Reasons          []Reason   `json:"reasons"`
	PolicyBundleHash string     `json:"policy_bundle_hash"`
	PayloadHash      string     `json:"payload_hash"`
	Approvals        []Approval `json:"approvals"`
	ReservationID    *string    `json:"reservation_id"`
	IssuedAt         time.Time  `json:"issued_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
}

// Approval is a human (or second-agent) countersignature on an escalation.
type Approval struct {
	Approver  string    `json:"approver"`
	At        time.Time `json:"at"`
	Signature string    `json:"signature"`
}

// AuditRecordType enumerates audit event kinds.
type AuditRecordType string

const (
	AuditRequest      AuditRecordType = "request"
	AuditDecision     AuditRecordType = "decision"
	AuditApproval     AuditRecordType = "approval"
	AuditPolicyChange AuditRecordType = "policy_change"
	AuditCommit       AuditRecordType = "commit"
	AuditRelease      AuditRecordType = "release"
	AuditOverride     AuditRecordType = "override"
)

// AuditRecord is one link in the hash chain (LLD §3.5, spec/audit-hash-v1.md).
type AuditRecord struct {
	Seq      uint64          `json:"seq"`
	TS       string          `json:"ts"` // RFC 3339, UTC, as stored; hashed verbatim
	Type     AuditRecordType `json:"type"`
	Body     any             `json:"body"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// ---- validation ----

// ValidationError lists every problem found, so clients fix them in one round trip.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid request: " + strings.Join(e.Problems, "; ")
}

var (
	reHexAddr = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	reHexData = regexp.MustCompile(`^0x([0-9a-fA-F]{2})*$`)
	reDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

// Validate checks structural invariants that do not depend on time or state.
// Freshness (clock skew, TTL expiry) and nonce replay are gateway concerns.
func (r ActionRequest) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }

	if r.ID == "" {
		add("id is required")
	}
	if r.Tenant == "" {
		add("tenant is required")
	}
	if len(r.Nonce) < 16 {
		add("nonce must be at least 16 characters")
	}
	if r.IssuedAt.IsZero() {
		add("issued_at is required")
	}
	if r.TTLSeconds <= 0 || time.Duration(r.TTLSeconds)*time.Second > MaxTTL {
		add("ttl_seconds must be in 1..%d", int(MaxTTL.Seconds()))
	}
	if r.Actor.AgentID == "" {
		add("actor.agent_id is required")
	}
	if r.Provenance.Labels == nil {
		add("provenance.labels is required (use [] for none)")
	}

	a := r.Action
	switch a.Kind {
	case KindEVMTx:
		if a.ChainID == nil || *a.ChainID == 0 {
			add("action.chain_id is required for evm_tx")
		}
		if !reHexAddr.MatchString(a.From) {
			add("action.from must be a 0x-prefixed 20-byte address")
		}
		if !reHexAddr.MatchString(a.To) {
			add("action.to must be a 0x-prefixed 20-byte address")
		}
		if !reDecimal.MatchString(a.ValueWei) {
			add("action.value_wei must be a non-negative decimal integer string")
		} else if v, _ := new(big.Int).SetString(a.ValueWei, 10); v.BitLen() > 256 {
			add("action.value_wei exceeds uint256")
		}
		if a.Data != "" && !reHexData.MatchString(a.Data) {
			add("action.data must be 0x-prefixed even-length hex")
		}
	case KindToolCall:
		if a.Tool == nil || *a.Tool == "" {
			add("action.tool is required for tool_call")
		}
	case KindWithdrawal:
		if a.To == "" {
			add("action.to is required for withdrawal")
		}
	default:
		add("action.kind must be one of evm_tx, tool_call, withdrawal")
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// ExpiresAt is when the request stops being valid.
func (r ActionRequest) ExpiresAt() time.Time {
	return r.IssuedAt.Add(time.Duration(r.TTLSeconds) * time.Second)
}

// ErrInvalidOutcome is returned for an unknown decision outcome.
var ErrInvalidOutcome = errors.New("model: invalid outcome")

// Validate checks a Decision is internally consistent. A deny or escalate must
// say why; nothing may be allowed without a bound policy bundle and payload.
func (d Decision) Validate() error {
	switch d.Outcome {
	case Allow, Deny, Escalate:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOutcome, d.Outcome)
	}
	if d.RequestID == "" {
		return errors.New("model: decision.request_id is required")
	}
	if d.Outcome != Allow && len(d.Reasons) == 0 {
		return errors.New("model: deny/escalate decisions must carry at least one reason")
	}
	if d.Outcome == Allow && (d.PolicyBundleHash == "" || d.PayloadHash == "") {
		return errors.New("model: allow decisions must bind policy_bundle_hash and payload_hash")
	}
	if !d.ExpiresAt.After(d.IssuedAt) {
		return errors.New("model: decision.expires_at must be after issued_at")
	}
	return nil
}
