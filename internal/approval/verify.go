package approval

import (
	"crypto/ed25519"
	"time"
)

// MaxExpiryAhead bounds how far in the future a signature's expiry may be,
// checked at verification time (spec §6/§8 steps 8-9): the gap between the
// claimed expiry and the verifier's clock can never exceed one hour.
const MaxExpiryAhead = time.Hour

// VerifyError carries the spec §6/§8 error code.
type VerifyError struct{ Code string }

func (e *VerifyError) Error() string { return "approval signature: " + e.Code }

func verr(code string) error { return &VerifyError{Code: code} }

// Error codes (spec §6, §8).
const (
	CodeUnknownKey        = "UNKNOWN_KEY"
	CodeWrongTenant       = "WRONG_TENANT"
	CodeMalformed         = "MALFORMED"
	CodeBadSignature      = "BAD_SIGNATURE"
	CodeBadDecision       = "BAD_DECISION"
	CodeWrongEscalationID = "WRONG_ESCALATION_ID"
	CodePayloadMismatch   = "PAYLOAD_MISMATCH"
	CodeExpired           = "EXPIRED"
	CodeExpiryTooFarAhead = "EXPIRY_TOO_FAR_AHEAD"
	CodeSelfApproval      = "SELF_APPROVAL"
	CodeWrongTrip         = "WRONG_TRIP"
)

// EscalationWant is the escalation's current state, recomputed by the
// caller (never taken from the envelope being verified): the id being
// resolved, the payload hash of the action about to be re-run, and the
// requester's identity for the self-approval check (spec §7) — both
// RequesterKeyID and RequesterAgentID from the escalation's authenticated
// requester (auth.Identity / PendingEscalation.Requester). Either may be
// checked: a self-approval match on KeyID OR AgentID refuses the approval.
type EscalationWant struct {
	EscalationID     string
	PayloadHash      string
	RequesterKeyID   string
	RequesterAgentID string
}

// VerifyEscalation checks s against keys (the tenant's configured
// approvers), want (the escalation's current state) and now, in the exact
// order of spec §6. It returns the matched key only if every check passes.
func VerifyEscalation(keys *KeySet, tenant string, s SignedEscalation, want EscalationWant, now time.Time) (Key, error) {
	k, ok := keys.Lookup(s.Kid)
	if !ok {
		return Key{}, verr(CodeUnknownKey)
	}
	if k.Tenant != tenant {
		return Key{}, verr(CodeWrongTenant)
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Key{}, verr(CodeMalformed)
	}
	msg, err := canonicalEscalation(s.EscalationObject)
	if err != nil {
		return Key{}, verr(CodeMalformed)
	}
	if !ed25519.Verify(k.Public, msg, sig) {
		return Key{}, verr(CodeBadSignature)
	}
	if s.Decision != Approve && s.Decision != Reject {
		return Key{}, verr(CodeBadDecision)
	}
	if s.EscalationID != want.EscalationID {
		return Key{}, verr(CodeWrongEscalationID)
	}
	if s.PayloadHash != want.PayloadHash {
		return Key{}, verr(CodePayloadMismatch)
	}
	if !now.Before(time.Unix(s.Expiry, 0)) {
		return Key{}, verr(CodeExpired)
	}
	if s.Expiry-now.Unix() > int64(MaxExpiryAhead/time.Second) {
		return Key{}, verr(CodeExpiryTooFarAhead)
	}
	if s.Decision == Approve && selfApproval(k.Owner, want) {
		return Key{}, verr(CodeSelfApproval)
	}
	return k, nil
}

// selfApproval reports whether owner (the matched key's configured
// binding) is the same identity as the escalation's requester, by either
// KeyID or AgentID (spec §7). An empty field on either side never matches
// an empty field on the other: Owner is required to be non-empty at
// config load (KeySet), but want's requester fields may legitimately be
// unset (e.g. no auth).
func selfApproval(owner Owner, want EscalationWant) bool {
	if owner.KeyID != "" && want.RequesterKeyID != "" && owner.KeyID == want.RequesterKeyID {
		return true
	}
	if owner.AgentID != "" && want.RequesterAgentID != "" && owner.AgentID == want.RequesterAgentID {
		return true
	}
	return false
}

// BreakerResetWant is the breaker's current state: the tenant being reset
// and the trip the reset must be bound to.
type BreakerResetWant struct {
	Tenant        string
	TripRequestID string
}

// VerifyBreakerReset checks s against keys, want and now, in the exact
// order of spec §8.
func VerifyBreakerReset(keys *KeySet, s SignedBreakerReset, want BreakerResetWant, now time.Time) (Key, error) {
	k, ok := keys.Lookup(s.Kid)
	if !ok {
		return Key{}, verr(CodeUnknownKey)
	}
	if k.Tenant != want.Tenant {
		return Key{}, verr(CodeWrongTenant)
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Key{}, verr(CodeMalformed)
	}
	msg, err := canonicalBreakerReset(s.BreakerResetObject)
	if err != nil {
		return Key{}, verr(CodeMalformed)
	}
	if !ed25519.Verify(k.Public, msg, sig) {
		return Key{}, verr(CodeBadSignature)
	}
	if s.Decision != ResetDecision {
		return Key{}, verr(CodeBadDecision)
	}
	if s.Tenant != want.Tenant {
		return Key{}, verr(CodeWrongTenant)
	}
	if s.TripRequestID != want.TripRequestID {
		return Key{}, verr(CodeWrongTrip)
	}
	if !now.Before(time.Unix(s.Expiry, 0)) {
		return Key{}, verr(CodeExpired)
	}
	if s.Expiry-now.Unix() > int64(MaxExpiryAhead/time.Second) {
		return Key{}, verr(CodeExpiryTooFarAhead)
	}
	return k, nil
}
