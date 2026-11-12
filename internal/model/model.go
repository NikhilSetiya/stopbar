// Package model defines Stopbar's wire types (LLD §3). JSON shapes here are
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
	Kind     ActionKind `json:"kind"`
	ChainID  *uint64    `json:"chain_id,omitempty"`
	From     string     `json:"from,omitempty"`
	To       string     `json:"to,omitempty"`
	ValueWei string     `json:"value_wei,omitempty"`
	Data     string     `json:"data,omitempty"`
	// The rest of the unsigned EVM transaction. All of it is bound by
	// payload_hash: the signer adapter fills in nothing after the decision
	// (decision-token-v1 §2.1). Only EIP-1559 (type 2) is supported.
	TxType               *int           `json:"tx_type,omitempty"`
	TxNonce              string         `json:"tx_nonce,omitempty"`
	GasLimit             string         `json:"gas_limit,omitempty"`
	MaxFeePerGas         string         `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas string         `json:"max_priority_fee_per_gas,omitempty"`
	Tool                 *string        `json:"tool"`
	Args                 map[string]any `json:"args"`
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
//
// Kind is the policy action (transfer, approve, contract_call). Op names the
// exact operation (e.g. erc20_transfer, swap_exact_in, safe_exec). For a call
// that contains calls (multicall, Safe, MultiSend, Universal Router), Calls
// holds each inner intent, and Flags is the union of every flag found at any
// depth, so a flag can't hide inside a batch. Asset, Amount and Destination
// describe the single value-moving effect when there is exactly one; with
// several, they are empty and Flags has multi_transfer.
type IntentSummary struct {
	Kind        string          `json:"kind"`
	Op          string          `json:"op,omitempty"`
	Target      string          `json:"target,omitempty"` // contract called, for inner calls
	Asset       *Asset          `json:"asset,omitempty"`
	Amount      string          `json:"amount,omitempty"`
	Destination string          `json:"destination,omitempty"`
	Flags       []string        `json:"flags"`
	Human       string          `json:"human"`
	Calls       []IntentSummary `json:"calls,omitempty"`
	PayloadHash string          `json:"payload_hash"`
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
	Request   ActionRequest `json:"request"`
	Intent    IntentSummary `json:"intent"`
	AmountUSD *string       `json:"amount_usd"`
	// MaxFeeUSD is the most the transaction can spend on fees
	// (gas_limit × max_fee_per_gas, priced). The limiter counts it on top of
	// AmountUSD, so a zero-value transaction cannot burn ETH under a value cap.
	MaxFeeUSD  *string `json:"max_fee_usd"`
	PriceStale bool    `json:"price_stale"`
	// AmountTokens is the amount moved in token units (the asset's own decimals),
	// known from the decoded tx with no price. It backs a price-independent cap
	// so an unpriced transfer is never allowed unchecked. A policy that reads it
	// guards with `context has amount_tokens`.
	AmountTokens *string `json:"amount_tokens,omitempty"`
	PctOfBalance *string `json:"pct_of_balance"`
	// ApprovalUSD is the value an approval would let the spender move, for a
	// bounded approval with a known price. Absent for unlimited approvals and
	// for everything that isn't an approval: a policy must check
	// `context has approval_usd`, so a missing value can only deny.
	ApprovalUSD            *string             `json:"approval_usd,omitempty"`
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

// Reason explains one contribution to a decision. Code is machine-readable:
// "POLICY" for a matched policy (PolicyID set), otherwise an engine code such
// as FAIL_CLOSED_DECODER or CAP_EXCEEDED (LLD §12).
type Reason struct {
	Code     string `json:"code,omitempty"`
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
	// Token is the decision token (spec/decision-token-v1.md), present only
	// on allow. It is not part of what it signs.
	Token string `json:"token,omitempty"`
	// SignedTx and TxHash are set in gatekeeper mode: the raw signed
	// transaction, ready to broadcast, and its hash. Allow only.
	SignedTx string `json:"signed_tx,omitempty"`
	TxHash   string `json:"tx_hash,omitempty"`
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
	AuditAuthReject   AuditRecordType = "auth_reject" // CS-103: a request rejected at the gateway (identity mismatch, scope)
)

// ErrNoPending means no escalation with that id is awaiting approval (CS-151).
var ErrNoPending = errors.New("no pending escalation for that id")

// AuditEntry is an audit record before the log assigns its sequence number,
// timestamp and hashes. State stores take one so that the record is written
// in the same transaction as the state change it describes.
type AuditEntry struct {
	Type AuditRecordType
	Body any
}

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
	reSHA256  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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
		if a.TxType == nil || *a.TxType != 2 {
			add("action.tx_type must be 2 (EIP-1559)")
		}
		num := func(name, v string, bits int) *big.Int {
			if !reDecimal.MatchString(v) {
				add("action.%s must be a non-negative decimal integer string", name)
				return nil
			}
			n, _ := new(big.Int).SetString(v, 10)
			if n.BitLen() > bits {
				add("action.%s exceeds uint%d", name, bits)
				return nil
			}
			return n
		}
		num("tx_nonce", a.TxNonce, 64)
		if g := num("gas_limit", a.GasLimit, 64); g != nil && g.Cmp(big.NewInt(21000)) < 0 {
			add("action.gas_limit must be at least 21000")
		}
		maxFee := num("max_fee_per_gas", a.MaxFeePerGas, 256)
		tip := num("max_priority_fee_per_gas", a.MaxPriorityFeePerGas, 256)
		if maxFee != nil && tip != nil && tip.Cmp(maxFee) > 0 {
			add("action.max_priority_fee_per_gas must not exceed max_fee_per_gas")
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
	if d.Outcome != Allow && (d.Token != "" || d.SignedTx != "" || d.TxHash != "") {
		return errors.New("model: only allow decisions may carry a token or signed transaction")
	}
	if d.Outcome == Allow && (d.PolicyBundleHash == "" || d.PayloadHash == "") {
		return errors.New("model: allow decisions must bind policy_bundle_hash and payload_hash")
	}
	for name, h := range map[string]string{"policy_bundle_hash": d.PolicyBundleHash, "payload_hash": d.PayloadHash} {
		if h != "" && !reSHA256.MatchString(h) {
			return fmt.Errorf("model: decision.%s must be sha256:<64 lower-case hex> (spec/decision-token-v1.md §2)", name)
		}
	}
	if !d.ExpiresAt.After(d.IssuedAt) {
		return errors.New("model: decision.expires_at must be after issued_at")
	}
	return nil
}
