package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Token constants (spec §3, §4).
const (
	TokenType  = "stopbar-decision+jws"
	MaxTTL     = 300 // seconds, = model.MaxTTL
	ClockSkew  = 5 * time.Second
	keyFileTag = "stopbar-decision-key-ed25519-v1\n"
)

var b64 = base64.RawURLEncoding.Strict()

// Claims is the exact claim set of spec §3.2.
type Claims struct {
	V                int           `json:"v"`
	Iss              string        `json:"iss"`
	Aud              string        `json:"aud"`
	Tenant           string        `json:"tenant"`
	RequestID        string        `json:"request_id"`
	Nonce            string        `json:"nonce"`
	Outcome          model.Outcome `json:"outcome"`
	PayloadHash      string        `json:"payload_hash"`
	PolicyBundleHash string        `json:"policy_bundle_hash"`
	ReservationID    *string       `json:"reservation_id"`
	Iat              int64         `json:"iat"`
	Exp              int64         `json:"exp"`
}

var claimNames = []string{"aud", "exp", "iat", "iss", "nonce", "outcome", "payload_hash",
	"policy_bundle_hash", "request_id", "reservation_id", "tenant", "v"}

// Kid is the RFC 7638 JWK thumbprint of an Ed25519 public key.
func Kid(pub ed25519.PublicKey) string {
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return b64.EncodeToString(sum[:])
}

// JWK is a public decision key as served at /v1/keys (RFC 8037 OKP). It is
// Stopbar's own type, so the core needs no JOSE library.
type JWK struct {
	Kty    string `json:"kty"`    // "OKP"
	Crv    string `json:"crv"`    // "Ed25519"
	X      string `json:"x"`      // base64url public key
	Kid    string `json:"kid"`    // RFC 7638 thumbprint
	Alg    string `json:"alg"`    // "EdDSA"
	Use    string `json:"use"`    // "sig"
	Status string `json:"status"` // "active" (signs and verifies) or "retired" (verifies only)
}

// KeyRing holds one active signing key and any number of retired keys.
// Rotation: Rotate makes a new key active and retires the old one, which
// keeps verifying tokens it issued but never signs again.
type KeyRing struct {
	mu      sync.RWMutex
	active  ed25519.PrivateKey
	retired map[string]ed25519.PublicKey
}

// NewKeyRing returns a ring whose active key is priv.
func NewKeyRing(priv ed25519.PrivateKey) *KeyRing {
	return &KeyRing{active: priv, retired: map[string]ed25519.PublicKey{}}
}

// Rotate retires the active key and makes next active.
func (k *KeyRing) Rotate(next ed25519.PrivateKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	old := k.active.Public().(ed25519.PublicKey)
	k.retired[Kid(old)] = old
	k.active = next
}

// ActiveKid is the kid new tokens are signed with.
func (k *KeyRing) ActiveKid() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return Kid(k.active.Public().(ed25519.PublicKey))
}

// PublicKeys maps every kid (active and retired) to its key, for verifiers.
func (k *KeyRing) PublicKeys() map[string]ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := map[string]ed25519.PublicKey{}
	for kid, pub := range k.retired {
		out[kid] = pub
	}
	pub := k.active.Public().(ed25519.PublicKey)
	out[Kid(pub)] = pub
	return out
}

// JWKS lists the ring for /v1/keys, active key first.
func (k *KeyRing) JWKS() []JWK {
	k.mu.RLock()
	defer k.mu.RUnlock()
	jwk := func(pub ed25519.PublicKey, status string) JWK {
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub), Kid: Kid(pub), Alg: "EdDSA", Use: "sig", Status: status}
	}
	out := []JWK{jwk(k.active.Public().(ed25519.PublicKey), "active")}
	for _, pub := range k.retired {
		out = append(out, jwk(pub, "retired"))
	}
	return out
}

// SignCheckpoint signs an audit checkpoint with the active key. Callers
// pass a domain-prefixed message (audit.CheckpointDomain), which can never
// be a token's signing input (that is two base64url segments).
func (k *KeyRing) SignCheckpoint(msg []byte) (kid string, sig []byte) { return k.sign(msg) }

func (k *KeyRing) sign(input []byte) (kid string, sig []byte) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return Kid(k.active.Public().(ed25519.PublicKey)), ed25519.Sign(k.active, input)
}

// Signer issues decision tokens (implements engine.Signer).
type Signer struct {
	Keys *KeyRing
	Iss  string // this deployment
	Aud  string // the signer adapter the token is for
}

// Sign builds the spec §3.2 claims from the request and decision and signs
// them with the active key.
func (s *Signer) Sign(_ context.Context, req model.ActionRequest, d model.Decision) (string, error) {
	if s.Keys == nil || s.Iss == "" || s.Aud == "" {
		return "", errors.New("decision: signer needs Keys, Iss and Aud")
	}
	if d.RequestID != req.ID {
		return "", errors.New("decision: decision is for a different request")
	}
	c := Claims{
		V: 1, Iss: s.Iss, Aud: s.Aud, Tenant: req.Tenant, RequestID: req.ID, Nonce: req.Nonce,
		Outcome: d.Outcome, PayloadHash: d.PayloadHash, PolicyBundleHash: d.PolicyBundleHash,
		ReservationID: d.ReservationID, Iat: d.IssuedAt.Unix(), Exp: d.ExpiresAt.Unix(),
	}
	if c.Exp <= c.Iat || c.Exp-c.Iat > MaxTTL {
		return "", fmt.Errorf("decision: token lifetime %ds outside (0, %d]", c.Exp-c.Iat, MaxTTL)
	}
	payload, err := canon.Marshal(c)
	if err != nil {
		return "", err
	}
	kid := s.Keys.ActiveKid()
	hdr, err := canon.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": TokenType})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	signedKid, sig := s.Keys.sign([]byte(input))
	if signedKid != kid { // rotated between header and signature
		return "", errors.New("decision: key rotated during signing; retry")
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// ---- verification (spec §4), in the normative order ----

// VerifyError carries the spec §4 error code.
type VerifyError struct{ Code string }

func (e *VerifyError) Error() string { return "decision token: " + e.Code }

func verr(code string) error { return &VerifyError{Code: code} }

// SpentStore is the single-use check of step 11 (nonce.Store satisfies it).
type SpentStore interface {
	Consume(key string, until time.Time) (fresh bool, err error)
}

// SpentRetention matches the gateway's nonce retention (max TTL + 2x skew).
const SpentRetention = model.MaxTTL + 2*30*time.Second

// Verifier is what a signer adapter runs before signing anything. Keys are
// pinned (never fetched from a token).
type Verifier struct {
	Keys             func() map[string]ed25519.PublicKey
	Iss, Aud, Tenant string
	Spent            SpentStore
	Clock            func() time.Time
}

// Verify runs spec §4 steps 0–11 against the exact action about to be
// signed. It returns the claims only if every step passes; the token is
// then spent and can never verify again.
func (v *Verifier) Verify(tok string, action model.Action) (Claims, error) {
	c, err := v.check(tok, action)
	if err != nil {
		return Claims{}, err
	}
	now := v.now()
	key := strconv.Quote(c.Iss) + "/" + strconv.Quote(c.Tenant) + "/" + strconv.Quote(c.Nonce)
	fresh, err := v.Spent.Consume(key, now.Add(SpentRetention))
	if err != nil {
		return Claims{}, fmt.Errorf("decision token: spent store unavailable: %w", err)
	}
	if !fresh {
		return Claims{}, verr("REPLAYED")
	}
	return c, nil
}

func (v *Verifier) now() time.Time {
	if v.Clock != nil {
		return v.Clock()
	}
	return time.Now()
}

// check is steps 0–10 (everything but spending).
func (v *Verifier) check(tok string, action model.Action) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, verr("MALFORMED")
	}
	var raw [3][]byte
	for i, p := range parts {
		b, err := b64.DecodeString(p)
		if err != nil {
			return Claims{}, verr("MALFORMED")
		}
		raw[i] = b
	}
	hdr, payload, sig := raw[0], raw[1], raw[2]

	// 1. Header: canonical, exactly {alg, kid, typ}, alg EdDSA. Anything else
	// (none, HS256, crit, jku, jwk, x5u) is rejected, never interpreted.
	var h map[string]string
	if c, err := canon.Transform(hdr); err != nil || !bytes.Equal(c, hdr) ||
		json.Unmarshal(hdr, &h) != nil || len(h) != 3 ||
		h["alg"] != "EdDSA" || h["typ"] != TokenType || h["kid"] == "" {
		return Claims{}, verr("BAD_HEADER")
	}
	// 2. Pinned keys only.
	pub, ok := v.Keys()[h["kid"]]
	if !ok {
		return Claims{}, verr("UNKNOWN_KEY")
	}
	// 3. Signature before any claim is read.
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, verr("BAD_SIGNATURE")
	}
	// 4. Canonical payload (also rejects duplicate members).
	if c, err := canon.Transform(payload); err != nil || !bytes.Equal(c, payload) {
		return Claims{}, verr("NON_CANONICAL")
	}
	// 5. Exactly the twelve claims, each of the right type.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil || len(m) != len(claimNames) {
		return Claims{}, verr("BAD_CLAIMS")
	}
	for _, n := range claimNames {
		if _, ok := m[n]; !ok {
			return Claims{}, verr("BAD_CLAIMS")
		}
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Claims{}, verr("BAD_CLAIMS")
	}
	// 6. Version.
	if c.V != 1 {
		return Claims{}, verr("BAD_VERSION")
	}
	// 7. From and for whom.
	switch {
	case c.Iss != v.Iss:
		return Claims{}, verr("WRONG_ISSUER")
	case c.Aud != v.Aud:
		return Claims{}, verr("WRONG_AUDIENCE")
	case c.Tenant != v.Tenant:
		return Claims{}, verr("WRONG_TENANT")
	}
	// 8. Time.
	now := v.now().Unix()
	if c.Exp <= c.Iat || c.Exp-c.Iat > MaxTTL {
		return Claims{}, verr("TTL_INVALID")
	}
	if c.Iat > now+int64(ClockSkew/time.Second) {
		return Claims{}, verr("NOT_YET_VALID")
	}
	if now >= c.Exp {
		return Claims{}, verr("EXPIRED")
	}
	// 9. Only allow authorises signing.
	if c.Outcome != model.Allow {
		return Claims{}, verr("NOT_ALLOWED")
	}
	// 10. Bound to exactly the action about to be signed, recomputed here.
	ph, err := PayloadHash(action)
	if err != nil || ph != c.PayloadHash {
		return Claims{}, verr("PAYLOAD_MISMATCH")
	}
	return c, nil
}

// ---- local key provider (dev only) ----

// LoadKeyFile reads a decision key written by WriteKeyFile. It refuses a
// file readable by anyone but its owner, and any file that is not a tagged
// decision key, so a wallet key file can never be loaded as one.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("decision: key file %s has mode %o; must be 0600 or stricter", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(string(b), keyFileTag)
	if !ok {
		return nil, fmt.Errorf("decision: %s is not a Stopbar decision key file", path)
	}
	seed, err := b64.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("decision: %s: malformed key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WriteKeyFile writes priv as a tagged decision key with mode 0600.
func WriteKeyFile(path string, priv ed25519.PrivateKey) error {
	return os.WriteFile(path, []byte(keyFileTag+b64.EncodeToString(priv.Seed())+"\n"), 0o600)
}
