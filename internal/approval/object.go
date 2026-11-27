package approval

import (
	"crypto/ed25519"

	"github.com/NikhilSetiya/stopbar/internal/canon"
)

// Decision strings for an escalation approval object (spec §2).
const (
	Approve = "approve"
	Reject  = "reject"
)

// ResetDecision is the only valid decision for a breaker reset object
// (spec §3); it is carried explicitly so a reset signature can never be
// mistaken for an escalation decision even if the domain tag were ignored.
const ResetDecision = "reset"

// Domain tags prefix the signing input of each object kind (spec §4), so a
// signature over one can never verify as the other, or as any other signed
// thing in the codebase (a decision token, an audit checkpoint). The
// escalation object is at v2 (spec §2: it binds policy_bundle_hash); the v1
// tag is never accepted, so a v1 signature cannot count as a vote.
const (
	escalationDomain   = "stopbar-approval-escalation-v2\n"
	breakerResetDomain = "stopbar-approval-breaker-reset-v1\n"
	contactDomain      = "stopbar-approval-contact-v1\n"
)

// EscalationObject is the exact JCS-canonical object an escalation
// approval signature covers (spec §2, v2).
type EscalationObject struct {
	EscalationID string `json:"escalation_id"`
	PayloadHash  string `json:"payload_hash"`
	// PolicyBundleHash is the active policy bundle the approver signed
	// against (policy.Bundle.Hash). A vote counts only while it still is.
	PolicyBundleHash string `json:"policy_bundle_hash"`
	Decision         string `json:"decision"` // Approve or Reject
	Expiry           int64  `json:"expiry"`   // unix seconds
}

// BreakerResetObject is the exact JCS-canonical object a breaker reset
// signature covers (spec §3).
type BreakerResetObject struct {
	Tenant        string `json:"tenant"`
	TripRequestID string `json:"trip_request_id"`
	Decision      string `json:"decision"` // always ResetDecision
	Expiry        int64  `json:"expiry"`
}

// ContactObject is the exact JCS-canonical object a destination-registry
// addition approval covers (spec §3a). Decision is always Approve: a
// pending addition is turned down by removing it, which needs no quorum.
type ContactObject struct {
	Tenant    string `json:"tenant"`
	ContactID string `json:"contact_id"`
	Address   string `json:"address"` // lowercase, as stored
	Decision  string `json:"decision"`
	Expiry    int64  `json:"expiry"`
}

// SignedEscalation is the wire envelope: the object plus who signed it and
// the signature (spec §4.1).
type SignedEscalation struct {
	EscalationObject
	Kid string `json:"kid"`
	Sig string `json:"sig"` // base64url, 64 bytes decoded
}

// SignedBreakerReset is the wire envelope for a breaker reset (spec §4.1).
type SignedBreakerReset struct {
	BreakerResetObject
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

// SignedContact is the wire envelope for a contact approval (spec §4.1).
type SignedContact struct {
	ContactObject
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

// canonicalEscalation returns domain || JCS(object) (spec §4).
func canonicalEscalation(o EscalationObject) ([]byte, error) {
	c, err := canon.Marshal(o)
	if err != nil {
		return nil, err
	}
	return append([]byte(escalationDomain), c...), nil
}

// canonicalBreakerReset returns domain || JCS(object) (spec §4).
func canonicalBreakerReset(o BreakerResetObject) ([]byte, error) {
	c, err := canon.Marshal(o)
	if err != nil {
		return nil, err
	}
	return append([]byte(breakerResetDomain), c...), nil
}

// SignEscalation signs o with priv and returns the full wire envelope
// (spec §4). The private key is only ever used here, locally, by whoever
// holds it — never sent anywhere.
func SignEscalation(priv ed25519.PrivateKey, o EscalationObject) (SignedEscalation, error) {
	msg, err := canonicalEscalation(o)
	if err != nil {
		return SignedEscalation{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return SignedEscalation{
		EscalationObject: o,
		Kid:              Kid(pub),
		Sig:              b64.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// SignBreakerReset signs o with priv and returns the full wire envelope
// (spec §4).
func SignBreakerReset(priv ed25519.PrivateKey, o BreakerResetObject) (SignedBreakerReset, error) {
	msg, err := canonicalBreakerReset(o)
	if err != nil {
		return SignedBreakerReset{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return SignedBreakerReset{
		BreakerResetObject: o,
		Kid:                Kid(pub),
		Sig:                b64.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// canonicalContact returns domain || JCS(object) (spec §4).
func canonicalContact(o ContactObject) ([]byte, error) {
	c, err := canon.Marshal(o)
	if err != nil {
		return nil, err
	}
	return append([]byte(contactDomain), c...), nil
}

// SignContact signs o with priv and returns the full wire envelope (spec §4).
func SignContact(priv ed25519.PrivateKey, o ContactObject) (SignedContact, error) {
	msg, err := canonicalContact(o)
	if err != nil {
		return SignedContact{}, err
	}
	return SignedContact{ContactObject: o, Kid: Kid(priv.Public().(ed25519.PublicKey)),
		Sig: b64.EncodeToString(ed25519.Sign(priv, msg))}, nil
}
