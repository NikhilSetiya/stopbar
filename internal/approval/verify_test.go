package approval

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// fixture holds a configured tenant key set plus the raw keys needed to
// forge adversarial signatures in the negative tests below.
type fixture struct {
	set            *KeySet
	alicePriv      ed25519.PrivateKey
	bobPriv        ed25519.PrivateKey
	aliceKid       string
	bobKid         string
	outsiderPriv   ed25519.PrivateKey // never configured: UNKNOWN_KEY
	otherTenantKid string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	alicePub, alicePriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bobPub, bobPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, outsiderPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewKeySet([]Key{
		{ID: "alice", Tenant: "acme", Public: alicePub},
		{ID: "bob", Tenant: "acme", AgentID: "bob-agent", Public: bobPub},
		{ID: "carol", Tenant: "other-tenant", Public: otherPub},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		set: set, alicePriv: alicePriv, bobPriv: bobPriv,
		aliceKid: Kid(alicePub), bobKid: Kid(bobPub),
		outsiderPriv: outsiderPriv, otherTenantKid: Kid(otherPub),
	}
}

const (
	wantEscID   = "esc_1"
	wantPayload = "sha256:abc"
)

func (f fixture) wantEsc() EscalationWant {
	return EscalationWant{EscalationID: wantEscID, PayloadHash: wantPayload}
}

func signEsc(t *testing.T, priv ed25519.PrivateKey, mut func(*EscalationObject)) SignedEscalation {
	t.Helper()
	obj := EscalationObject{EscalationID: wantEscID, PayloadHash: wantPayload, Decision: Approve, Expiry: time.Now().Add(30 * time.Minute).Unix()}
	if mut != nil {
		mut(&obj)
	}
	s, err := SignEscalation(priv, obj)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyEscalationHappyPath(t *testing.T) {
	f := newFixture(t)
	s := signEsc(t, f.alicePriv, nil)
	k, err := VerifyEscalation(f.set, "acme", s, f.wantEsc(), time.Now())
	if err != nil {
		t.Fatalf("VerifyEscalation: %v", err)
	}
	if k.ID != "alice" {
		t.Fatalf("matched key = %s, want alice", k.ID)
	}
}

func TestVerifyEscalationRejectHappyPath(t *testing.T) {
	f := newFixture(t)
	s := signEsc(t, f.bobPriv, func(o *EscalationObject) { o.Decision = Reject })
	if _, err := VerifyEscalation(f.set, "acme", s, f.wantEsc(), time.Now()); err != nil {
		t.Fatalf("VerifyEscalation(reject): %v", err)
	}
}

func TestVerifyEscalationFailureCases(t *testing.T) {
	f := newFixture(t)
	now := time.Now()

	cases := []struct {
		name string
		s    func() SignedEscalation
		want string
	}{
		{
			name: "wrong payload_hash",
			s: func() SignedEscalation {
				return signEsc(t, f.alicePriv, func(o *EscalationObject) { o.PayloadHash = "sha256:different" })
			},
			want: CodePayloadMismatch,
		},
		{
			name: "wrong escalation_id",
			s: func() SignedEscalation {
				return signEsc(t, f.alicePriv, func(o *EscalationObject) { o.EscalationID = "esc_other" })
			},
			want: CodeWrongEscalationID,
		},
		{
			name: "replayed signature on another escalation",
			s: func() SignedEscalation {
				// Validly signed for esc_2, replayed against esc_1's want.
				obj := EscalationObject{EscalationID: "esc_2", PayloadHash: wantPayload, Decision: Approve, Expiry: now.Add(30 * time.Minute).Unix()}
				s, err := SignEscalation(f.alicePriv, obj)
				if err != nil {
					t.Fatal(err)
				}
				return s
			},
			want: CodeWrongEscalationID,
		},
		{
			name: "wrong decision",
			s: func() SignedEscalation {
				return signEsc(t, f.alicePriv, func(o *EscalationObject) { o.Decision = "maybe" })
			},
			want: CodeBadDecision,
		},
		{
			name: "expired signature",
			s: func() SignedEscalation {
				return signEsc(t, f.alicePriv, func(o *EscalationObject) { o.Expiry = now.Add(-time.Second).Unix() })
			},
			want: CodeExpired,
		},
		{
			name: "expiry too far ahead",
			s: func() SignedEscalation {
				return signEsc(t, f.alicePriv, func(o *EscalationObject) { o.Expiry = now.Add(2 * time.Hour).Unix() })
			},
			want: CodeExpiryTooFarAhead,
		},
		{
			name: "unknown key",
			s:    func() SignedEscalation { return signEsc(t, f.outsiderPriv, nil) },
			want: CodeUnknownKey,
		},
		{
			name: "key of another tenant",
			s:    func() SignedEscalation { return signEsc(t, f.alicePriv, nil) }, // signed fine, but verified against "other-tenant" below
			want: CodeWrongTenant,
		},
		{
			name: "malformed signature encoding",
			s: func() SignedEscalation {
				s := signEsc(t, f.alicePriv, nil)
				s.Sig = "not-valid-base64url!!!"
				return s
			},
			want: CodeMalformed,
		},
		{
			name: "malformed signature length",
			s: func() SignedEscalation {
				s := signEsc(t, f.alicePriv, nil)
				s.Sig = b64.EncodeToString([]byte("too-short"))
				return s
			},
			want: CodeMalformed,
		},
		{
			name: "tampered object under a valid-looking signature",
			s: func() SignedEscalation {
				s := signEsc(t, f.alicePriv, nil)
				s.PayloadHash = "sha256:tampered"
				return s
			},
			want: CodeBadSignature,
		},
		{
			name: "signature by an unconfigured key (stand-in for an API key, which has no approver entry)",
			s:    func() SignedEscalation { return signEsc(t, f.outsiderPriv, nil) },
			want: CodeUnknownKey,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tenant := "acme"
			if c.name == "key of another tenant" {
				tenant = "other-tenant"
			}
			_, err := VerifyEscalation(f.set, tenant, c.s(), f.wantEsc(), now)
			ve, ok := err.(*VerifyError)
			if !ok {
				t.Fatalf("err = %v, want *VerifyError", err)
			}
			if ve.Code != c.want {
				t.Fatalf("code = %s, want %s", ve.Code, c.want)
			}
		})
	}
}

func TestVerifyEscalationSelfApproval(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	s := signEsc(t, f.bobPriv, nil) // bob is configured with AgentID "bob-agent"

	// The escalation's requester is a different agent: fine.
	want := f.wantEsc()
	want.RequesterID = "someone-else"
	if _, err := VerifyEscalation(f.set, "acme", s, want, now); err != nil {
		t.Fatalf("VerifyEscalation (different requester): %v", err)
	}

	// The escalation's requester IS bob's bound agent: self-approval.
	want.RequesterID = "bob-agent"
	_, err := VerifyEscalation(f.set, "acme", s, want, now)
	ve, ok := err.(*VerifyError)
	if !ok || ve.Code != CodeSelfApproval {
		t.Fatalf("err = %v, want SELF_APPROVAL", err)
	}
}

func TestVerifyEscalationSelfApprovalDoesNotBlockReject(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	s := signEsc(t, f.bobPriv, func(o *EscalationObject) { o.Decision = Reject })
	want := f.wantEsc()
	want.RequesterID = "bob-agent"
	// Self-approval (spec §7) names approval, not reject; a bound approver
	// may still reject its own escalation.
	if _, err := VerifyEscalation(f.set, "acme", s, want, now); err != nil {
		t.Fatalf("VerifyEscalation (self-reject): %v", err)
	}
}

// ---- breaker reset ----

func (f fixture) wantReset() BreakerResetWant {
	return BreakerResetWant{Tenant: "acme", TripRequestID: "req_1"}
}

func signReset(t *testing.T, priv ed25519.PrivateKey, mut func(*BreakerResetObject)) SignedBreakerReset {
	t.Helper()
	obj := BreakerResetObject{Tenant: "acme", TripRequestID: "req_1", Decision: ResetDecision, Expiry: time.Now().Add(30 * time.Minute).Unix()}
	if mut != nil {
		mut(&obj)
	}
	s, err := SignBreakerReset(priv, obj)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyBreakerResetHappyPath(t *testing.T) {
	f := newFixture(t)
	s := signReset(t, f.alicePriv, nil)
	if _, err := VerifyBreakerReset(f.set, s, f.wantReset(), time.Now()); err != nil {
		t.Fatalf("VerifyBreakerReset: %v", err)
	}
}

func TestVerifyBreakerResetFailureCases(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	cases := []struct {
		name   string
		s      func() SignedBreakerReset
		tenant string
		want   string
	}{
		{name: "wrong tenant in object", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.Tenant = "other-tenant" })
		}, tenant: "acme", want: CodeWrongTenant},
		{name: "wrong trip id", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.TripRequestID = "req_other" })
		}, tenant: "acme", want: CodeWrongTrip},
		{name: "replayed signature on a later trip", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.TripRequestID = "req_2" })
		}, tenant: "acme", want: CodeWrongTrip},
		{name: "wrong decision", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.Decision = "approve" })
		}, tenant: "acme", want: CodeBadDecision},
		{name: "expired signature", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.Expiry = now.Add(-time.Second).Unix() })
		}, tenant: "acme", want: CodeExpired},
		{name: "expiry too far ahead", s: func() SignedBreakerReset {
			return signReset(t, f.alicePriv, func(o *BreakerResetObject) { o.Expiry = now.Add(2 * time.Hour).Unix() })
		}, tenant: "acme", want: CodeExpiryTooFarAhead},
		{name: "unknown key", s: func() SignedBreakerReset { return signReset(t, f.outsiderPriv, nil) }, tenant: "acme", want: CodeUnknownKey},
		{name: "key of another tenant", s: func() SignedBreakerReset { return signReset(t, f.alicePriv, nil) }, tenant: "other-tenant", want: CodeWrongTenant},
		{name: "malformed signature encoding", s: func() SignedBreakerReset {
			s := signReset(t, f.alicePriv, nil)
			s.Sig = "***not-base64url***"
			return s
		}, tenant: "acme", want: CodeMalformed},
		{name: "tampered object under a valid-looking signature", s: func() SignedBreakerReset {
			s := signReset(t, f.alicePriv, nil)
			s.TripRequestID = "req_tampered"
			return s
		}, tenant: "acme", want: CodeBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := BreakerResetWant{Tenant: c.tenant, TripRequestID: "req_1"}
			_, err := VerifyBreakerReset(f.set, c.s(), want, now)
			ve, ok := err.(*VerifyError)
			if !ok {
				t.Fatalf("err = %v, want *VerifyError", err)
			}
			if ve.Code != c.want {
				t.Fatalf("code = %s, want %s", ve.Code, c.want)
			}
		})
	}
}
