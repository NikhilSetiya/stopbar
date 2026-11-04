package decision

// Reference implementation of spec/decision-token-v1.md, used only to
// generate and check spec/vectors/decision-token-v1.json. CS-161 (signer) and
// CS-162 (adapter verifier) implement against these vectors.
//
// Regenerate: go test ./internal/decision -run TestDecisionTokenVectors -update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

var update = flag.Bool("update", false, "rewrite spec/vectors/decision-token-v1.json")

const (
	vectorsFile = "../../spec/vectors/decision-token-v1.json"
	tokenType   = "stopbar-decision+jws"
	maxTokenTTL = 300 // seconds, = model.MaxTTL
	clockSkew   = 5   // seconds
	maxSafeInt  = 1 << 53
)

var b64 = base64.RawURLEncoding.Strict()

// ---- payload binding (spec §2) ----

func canonicalAction(a model.Action) ([]byte, error) {
	var obj map[string]any
	switch a.Kind {
	case model.KindEVMTx:
		if a.ChainID == nil || *a.ChainID == 0 || *a.ChainID >= maxSafeInt {
			return nil, errors.New("evm_tx: chain_id must be in [1, 2^53)")
		}
		v, ok := new(big.Int).SetString(a.ValueWei, 10)
		if !ok || v.Sign() < 0 {
			return nil, errors.New("evm_tx: value_wei must be a non-negative decimal string")
		}
		obj = map[string]any{
			"v": 1, "kind": "evm_tx", "chain_id": *a.ChainID,
			"from": strings.ToLower(a.From), "to": strings.ToLower(a.To),
			"value_wei": v.String(), "data": strings.ToLower(a.Data),
		}
	case model.KindToolCall:
		if a.Tool == nil || *a.Tool == "" {
			return nil, errors.New("tool_call: tool required")
		}
		args := a.Args
		if args == nil {
			args = map[string]any{}
		}
		obj = map[string]any{"v": 1, "kind": "tool_call", "tool": *a.Tool, "args": args}
	default:
		return nil, fmt.Errorf("%s: no payload binding in v1", a.Kind)
	}
	return canon.Marshal(obj)
}

func payloadHash(a model.Action) (string, error) {
	c, err := canonicalAction(a)
	if err != nil {
		return "", err
	}
	return canon.Digest(c), nil
}

// ---- token (spec §3) ----

type claims struct {
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

// kid is the RFC 7638 JWK thumbprint of an Ed25519 public key.
func kid(pub ed25519.PublicKey) string {
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return b64.EncodeToString(sum[:])
}

func mustCanon(t testing.TB, v any) []byte {
	t.Helper()
	b, err := canon.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func header(k string) map[string]string {
	return map[string]string{"alg": "EdDSA", "kid": k, "typ": tokenType}
}

// signRaw signs arbitrary header/payload bytes, so vectors can carry
// deliberately malformed but validly signed tokens.
func signRaw(priv ed25519.PrivateKey, hdr, payload []byte) string {
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	return in + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

// ---- verification (spec §4), in the normative order ----

type tokenError string

func (e tokenError) Error() string { return string(e) }

type verifier struct {
	keys             map[string]ed25519.PublicKey
	iss, aud, tenant string
	seen             map[string]int64 // replay key -> exp
}

func (v *verifier) verify(tok string, action model.Action, now int64) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return tokenError("MALFORMED")
	}
	var raw [3][]byte
	for i, p := range parts {
		b, err := b64.DecodeString(p)
		if err != nil {
			return tokenError("MALFORMED")
		}
		raw[i] = b
	}
	hdr, payload, sig := raw[0], raw[1], raw[2]

	// 1. Header: canonical, exactly {alg, kid, typ}, alg EdDSA.
	var h map[string]string
	if c, err := canon.Transform(hdr); err != nil || !bytes.Equal(c, hdr) ||
		json.Unmarshal(hdr, &h) != nil || len(h) != 3 ||
		h["alg"] != "EdDSA" || h["typ"] != tokenType || h["kid"] == "" {
		return tokenError("BAD_HEADER")
	}
	// 2. Key from the pinned set only.
	pub, ok := v.keys[h["kid"]]
	if !ok {
		return tokenError("UNKNOWN_KEY")
	}
	// 3. Signature, before any claim is read.
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return tokenError("BAD_SIGNATURE")
	}
	// 4. Payload canonical (also rejects duplicate members).
	if c, err := canon.Transform(payload); err != nil || !bytes.Equal(c, payload) {
		return tokenError("NON_CANONICAL")
	}
	// 5. Exact claim set.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil || len(m) != len(claimNames) {
		return tokenError("BAD_CLAIMS")
	}
	for _, n := range claimNames {
		if _, ok := m[n]; !ok {
			return tokenError("BAD_CLAIMS")
		}
	}
	var c claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return tokenError("BAD_CLAIMS")
	}
	// 6. Version.
	if c.V != 1 {
		return tokenError("BAD_VERSION")
	}
	// 7. Who it is from and for.
	switch {
	case c.Iss != v.iss:
		return tokenError("WRONG_ISSUER")
	case c.Aud != v.aud:
		return tokenError("WRONG_AUDIENCE")
	case c.Tenant != v.tenant:
		return tokenError("WRONG_TENANT")
	}
	// 8. Time.
	if c.Exp <= c.Iat || c.Exp-c.Iat > maxTokenTTL {
		return tokenError("TTL_INVALID")
	}
	if c.Iat > now+clockSkew {
		return tokenError("NOT_YET_VALID")
	}
	if now >= c.Exp {
		return tokenError("EXPIRED")
	}
	// 9. Only allow tokens authorise signing.
	if c.Outcome != model.Allow {
		return tokenError("NOT_ALLOWED")
	}
	// 10. Bound to exactly the action about to be signed.
	ph, err := payloadHash(action)
	if err != nil || ph != c.PayloadHash {
		return tokenError("PAYLOAD_MISMATCH")
	}
	// 11. Single use. Recorded only after every other check passed.
	key := c.Iss + "\x00" + c.Tenant + "\x00" + c.Nonce
	if _, dup := v.seen[key]; dup {
		return tokenError("REPLAYED")
	}
	v.seen[key] = c.Exp
	return nil
}

// ---- vectors ----

type vectorFile struct {
	Spec     string                  `json:"spec"`
	Note     string                  `json:"note"`
	Key      vectorKey               `json:"key"`
	Verifier vectorVerifier          `json:"verifier"`
	Actions  map[string]model.Action `json:"actions"`
	Payloads []payloadVector         `json:"payloads"`
	Tokens   []tokenVector           `json:"tokens"`
}

type vectorKey struct {
	SeedHex   string `json:"seed_hex"`
	PublicB64 string `json:"public_b64url"`
	Kid       string `json:"kid"`
}

type vectorVerifier struct {
	Iss    string `json:"iss"`
	Aud    string `json:"aud"`
	Tenant string `json:"tenant"`
}

type payloadVector struct {
	Action      string `json:"action"`
	Canonical   string `json:"canonical"`
	PayloadHash string `json:"payload_hash"`
}

type presentation struct {
	Action string `json:"action"`
	Now    int64  `json:"now"`
	Want   string `json:"want"`
}

type tokenVector struct {
	Name          string         `json:"name"`
	Token         string         `json:"token"`
	Presentations []presentation `json:"presentations"`
}

func ptr[T any](v T) *T { return &v }

func loadActionFixture(t *testing.T, path string) model.Action {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r model.ActionRequest
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Action
}

func buildVectors(t *testing.T) vectorFile {
	seed := sha256.Sum256([]byte("stopbar decision-token-v1 test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	k := kid(pub)
	otherSeed := sha256.Sum256([]byte("stopbar decision-token-v1 unpinned key"))
	other := ed25519.NewKeyFromSeed(otherSeed[:])

	evm := loadActionFixture(t, "../../spec/fixtures/action_request.evm_tx.json")
	tool := loadActionFixture(t, "../../spec/fixtures/action_request.tool_call.json")
	evmMixed := evm
	evmMixed.Data = "0x" + strings.ToUpper(evm.Data[2:]) // same bytes, upper-case hex
	evmMixed.ValueWei = "000"                            // same value, non-canonical form
	evmOtherTo := evm
	evmOtherTo.To = "0x9f30000000000000000000000000000000000c21"
	evmOtherValue := evm
	evmOtherValue.ValueWei = "1"
	actions := map[string]model.Action{
		"evm": evm, "evm_noncanonical_input": evmMixed, "evm_other_to": evmOtherTo,
		"evm_other_value": evmOtherValue, "tool_call": tool,
	}

	vf := vectorFile{
		Spec:     "decision-token-v1",
		Note:     "Generated by internal/decision/token_v1_test.go. Each token is presented to a fresh verifier, in order; 'want' is OK or an error code from spec §4.",
		Key:      vectorKey{SeedHex: fmt.Sprintf("%x", seed), PublicB64: b64.EncodeToString(pub), Kid: k},
		Verifier: vectorVerifier{Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme"},
		Actions:  actions,
	}
	names := make([]string, 0, len(actions))
	for n := range actions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c, err := canonicalAction(actions[n])
		if err != nil {
			t.Fatal(err)
		}
		vf.Payloads = append(vf.Payloads, payloadVector{Action: n, Canonical: string(c), PayloadHash: canon.Digest(c)})
	}

	iat := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC).Unix()
	now := iat + 10
	base := func(a model.Action) claims {
		ph, err := payloadHash(a)
		if err != nil {
			t.Fatal(err)
		}
		return claims{
			V: 1, Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme",
			RequestID: "req_01JD0000000000000000000001", Nonce: "Zml4dHVyZS1ub25jZS0wMDAx",
			Outcome: model.Allow, PayloadHash: ph,
			PolicyBundleHash: "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			ReservationID:    ptr("rsv_01JD0000000000000000000001"),
			Iat:              iat, Exp: iat + 60,
		}
	}
	sign := func(c claims) string { return signRaw(priv, mustCanon(t, header(k)), mustCanon(t, c)) }
	with := func(f func(*claims)) string { c := base(evm); f(&c); return sign(c) }
	once := func(action string, want string) []presentation {
		return []presentation{{Action: action, Now: now, Want: want}}
	}
	add := func(name, tok string, ps []presentation) {
		vf.Tokens = append(vf.Tokens, tokenVector{Name: name, Token: tok, Presentations: ps})
	}

	good := sign(base(evm))
	toolClaims := base(tool)
	toolClaims.RequestID, toolClaims.Nonce, toolClaims.ReservationID = "req_01JD0000000000000000000002", "dG9vbC1jYWxsLW5vbmNlLTAy", nil
	add("allow_evm", good, once("evm", "OK"))
	add("allow_evm_noncanonical_input", good, once("evm_noncanonical_input", "OK"))
	add("allow_tool_call", sign(toolClaims), once("tool_call", "OK"))
	add("replay", good, []presentation{{"evm", now, "OK"}, {"evm", now + 1, "REPLAYED"}})
	add("failed_check_does_not_consume_nonce", good, []presentation{{"evm_other_to", now, "PAYLOAD_MISMATCH"}, {"evm", now, "OK"}})
	add("payload_mismatch_to", good, once("evm_other_to", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_value", good, once("evm_other_value", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_kind", good, once("tool_call", "PAYLOAD_MISMATCH"))
	add("outcome_deny", with(func(c *claims) { c.Outcome = model.Deny }), once("evm", "NOT_ALLOWED"))
	add("outcome_escalate", with(func(c *claims) { c.Outcome = model.Escalate }), once("evm", "NOT_ALLOWED"))
	add("expired_at_exp", good, []presentation{{"evm", iat + 60, "EXPIRED"}})
	add("valid_just_before_exp", good, []presentation{{"evm", iat + 59, "OK"}})
	add("not_yet_valid", good, []presentation{{"evm", iat - clockSkew - 1, "NOT_YET_VALID"}})
	add("within_clock_skew", good, []presentation{{"evm", iat - clockSkew, "OK"}})
	add("ttl_too_long", with(func(c *claims) { c.Exp = c.Iat + maxTokenTTL + 1 }), once("evm", "TTL_INVALID"))
	add("exp_before_iat", with(func(c *claims) { c.Exp = c.Iat }), once("evm", "TTL_INVALID"))
	add("wrong_issuer", with(func(c *claims) { c.Iss = "stopbar:other" }), once("evm", "WRONG_ISSUER"))
	add("wrong_audience", with(func(c *claims) { c.Aud = "signer:other" }), once("evm", "WRONG_AUDIENCE"))
	add("wrong_tenant", with(func(c *claims) { c.Tenant = "other" }), once("evm", "WRONG_TENANT"))
	add("bad_version", with(func(c *claims) { c.V = 2 }), once("evm", "BAD_VERSION"))

	add("unknown_kid", signRaw(other, mustCanon(t, header(kid(other.Public().(ed25519.PublicKey)))), mustCanon(t, base(evm))), once("evm", "UNKNOWN_KEY"))
	add("pinned_kid_wrong_key", signRaw(other, mustCanon(t, header(k)), mustCanon(t, base(evm))), once("evm", "BAD_SIGNATURE"))
	denied := base(evm)
	denied.Outcome = model.Deny
	dp := strings.Split(sign(denied), ".")
	gp := strings.Split(good, ".")
	add("payload_swapped_under_signature", dp[0]+"."+gp[1]+"."+dp[2], once("evm", "BAD_SIGNATURE"))

	payload := mustCanon(t, base(evm))
	noneHdr := mustCanon(t, map[string]string{"alg": "none", "kid": k, "typ": tokenType})
	add("alg_none", b64.EncodeToString(noneHdr)+"."+b64.EncodeToString(payload)+".", once("evm", "BAD_HEADER"))
	add("alg_none_signed", signRaw(priv, noneHdr, payload), once("evm", "BAD_HEADER"))
	hsHdr := mustCanon(t, map[string]string{"alg": "HS256", "kid": k, "typ": tokenType})
	hsIn := b64.EncodeToString(hsHdr) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, pub) // classic alg confusion: public key as HMAC secret
	mac.Write([]byte(hsIn))
	add("alg_hs256_confusion", hsIn+"."+b64.EncodeToString(mac.Sum(nil)), once("evm", "BAD_HEADER"))
	jku := mustCanon(t, map[string]string{"alg": "EdDSA", "jku": "https://attacker.example/jwks", "kid": k, "typ": tokenType})
	add("header_extra_member", signRaw(priv, jku, payload), once("evm", "BAD_HEADER"))
	add("header_wrong_typ", signRaw(priv, mustCanon(t, map[string]string{"alg": "EdDSA", "kid": k, "typ": "JWT"}), payload), once("evm", "BAD_HEADER"))
	add("header_non_canonical", signRaw(priv, []byte(`{"typ":"`+tokenType+`","alg":"EdDSA","kid":"`+k+`"}`), payload), once("evm", "BAD_HEADER"))

	add("payload_whitespace", signRaw(priv, mustCanon(t, header(k)), append([]byte(" "), payload...)), once("evm", "NON_CANONICAL"))
	dup := bytes.Replace(payload, []byte(`{"aud"`), []byte(`{"aud":"x","aud"`), 1)
	add("payload_duplicate_member", signRaw(priv, mustCanon(t, header(k)), dup), once("evm", "NON_CANONICAL"))
	var extra map[string]any
	if err := json.Unmarshal(payload, &extra); err != nil {
		t.Fatal(err)
	}
	extra["admin"] = true
	add("unknown_claim", signRaw(priv, mustCanon(t, header(k)), mustCanon(t, extra)), once("evm", "BAD_CLAIMS"))
	delete(extra, "admin")
	delete(extra, "nonce")
	add("missing_claim", signRaw(priv, mustCanon(t, header(k)), mustCanon(t, extra)), once("evm", "BAD_CLAIMS"))

	add("two_segments", gp[0]+"."+gp[1], once("evm", "MALFORMED"))
	add("padded_base64", gp[0]+"."+gp[1]+"."+gp[2]+"==", once("evm", "MALFORMED"))
	return vf
}

func TestDecisionTokenVectors(t *testing.T) {
	vf := buildVectors(t)
	got, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(vectorsFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; regenerate with -update and review the diff", vectorsFile)
	}

	// Check the file as an independent implementer would: only from its contents.
	var file vectorFile
	if err := json.Unmarshal(want, &file); err != nil {
		t.Fatal(err)
	}
	for _, p := range file.Payloads {
		c, err := canonicalAction(file.Actions[p.Action])
		if err != nil || string(c) != p.Canonical || canon.Digest(c) != p.PayloadHash {
			t.Errorf("payload %s: canonical/hash mismatch (%v)", p.Action, err)
		}
	}
	pub, err := b64.DecodeString(file.Key.PublicB64)
	if err != nil || kid(pub) != file.Key.Kid {
		t.Fatalf("key/kid mismatch")
	}
	for _, tv := range file.Tokens {
		v := &verifier{
			keys: map[string]ed25519.PublicKey{file.Key.Kid: pub},
			iss:  file.Verifier.Iss, aud: file.Verifier.Aud, tenant: file.Verifier.Tenant,
			seen: map[string]int64{},
		}
		for i, p := range tv.Presentations {
			res := "OK"
			if err := v.verify(tv.Token, file.Actions[p.Action], p.Now); err != nil {
				res = err.Error()
			}
			if res != p.Want {
				t.Errorf("%s[%d]: got %s, want %s", tv.Name, i, res, p.Want)
			}
		}
	}
}

func TestPayloadHashRejectsUnbindable(t *testing.T) {
	big := uint64(maxSafeInt)
	for name, a := range map[string]model.Action{
		"withdrawal":        {Kind: model.KindWithdrawal},
		"evm no chain":      {Kind: model.KindEVMTx, ValueWei: "0"},
		"evm chain >= 2^53": {Kind: model.KindEVMTx, ChainID: &big, ValueWei: "0"},
		"evm negative":      {Kind: model.KindEVMTx, ChainID: ptr(uint64(1)), ValueWei: "-1"},
		"evm hex value":     {Kind: model.KindEVMTx, ChainID: ptr(uint64(1)), ValueWei: "0x10"},
		"tool no name":      {Kind: model.KindToolCall},
	} {
		if _, err := payloadHash(a); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
