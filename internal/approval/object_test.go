package approval

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestSignEscalationVerifiesWithRawEd25519(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	obj := EscalationObject{EscalationID: "esc_1", PayloadHash: "sha256:abc", Decision: Approve, Expiry: time.Now().Add(time.Minute).Unix()}
	s, err := SignEscalation(priv, obj)
	if err != nil {
		t.Fatal(err)
	}
	if s.Kid != Kid(pub) {
		t.Fatalf("Kid = %s, want %s", s.Kid, Kid(pub))
	}
	msg, err := canonicalEscalation(obj)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify against the canonical object")
	}
}

func TestSignBreakerResetVerifiesWithRawEd25519(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	obj := BreakerResetObject{Tenant: "acme", TripRequestID: "req_1", Decision: ResetDecision, Expiry: time.Now().Add(time.Minute).Unix()}
	s, err := SignBreakerReset(priv, obj)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := canonicalBreakerReset(obj)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify against the canonical object")
	}
}

// TestDomainsDoNotCollide guards the domain separation spec §4 relies on:
// an escalation signature must never verify as a breaker-reset signature
// even when the JSON shapes happen to carry the same decision string.
func TestDomainsDoNotCollide(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Minute).Unix()
	esc := EscalationObject{EscalationID: "same", PayloadHash: "same", Decision: Reject, Expiry: exp}
	s, err := SignEscalation(priv, esc)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil {
		t.Fatal(err)
	}
	// Try to read the escalation signature as a breaker reset over a
	// coincidentally similarly-shaped object.
	reset := BreakerResetObject{Tenant: "same", TripRequestID: "same", Decision: Reject, Expiry: exp}
	msg, err := canonicalBreakerReset(reset)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("an escalation signature verified as a breaker-reset signature")
	}
}

func TestCanonicalEscalationDiffersOnAnyFieldChange(t *testing.T) {
	base := EscalationObject{EscalationID: "e1", PayloadHash: "sha256:x", Decision: Approve, Expiry: 100}
	variants := []EscalationObject{
		{EscalationID: "e2", PayloadHash: "sha256:x", Decision: Approve, Expiry: 100},
		{EscalationID: "e1", PayloadHash: "sha256:y", Decision: Approve, Expiry: 100},
		{EscalationID: "e1", PayloadHash: "sha256:x", Decision: Reject, Expiry: 100},
		{EscalationID: "e1", PayloadHash: "sha256:x", Decision: Approve, Expiry: 101},
	}
	cb, err := canonicalEscalation(base)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range variants {
		cv, err := canonicalEscalation(v)
		if err != nil {
			t.Fatal(err)
		}
		if string(cv) == string(cb) {
			t.Fatalf("variant %d: canonical bytes equal base despite a changed field", i)
		}
	}
}
