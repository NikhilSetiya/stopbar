package decision

// Conformance vectors for spec/decision-token-v2.md. The vectors are
// generated here and checked against the PRODUCTION verifier (token.go), as
// any other implementation would check them. The frozen v1 vectors
// (spec/vectors/decision-token-v1.json) are kept and checked to be rejected.
//
// Regenerate: go test ./internal/decision -run TestDecisionTokenVectors -update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

var update = flag.Bool("update", false, "rewrite spec/vectors/decision-token-v2.json")

const (
	vectorsFile   = "../../spec/vectors/decision-token-v2.json"
	v1VectorsFile = "../../spec/vectors/decision-token-v1.json" // frozen: never regenerated
	v1TokenType   = "stopbar-decision+jws"
	clockSkew     = int64(ClockSkew / time.Second)
)

// mapSpent is an in-memory spent store for the vector run.
type mapSpent map[string]bool

func (m mapSpent) Consume(key string, _ time.Time) (bool, error) {
	if m[key] {
		return false, nil
	}
	m[key] = true
	return true, nil
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
	return map[string]string{"alg": "EdDSA", "kid": k, "typ": TokenType}
}

// signRaw signs arbitrary header/payload bytes, so vectors can carry
// deliberately malformed but validly signed tokens.
func signRaw(priv ed25519.PrivateKey, hdr, payload []byte) string {
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	return in + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

// ---- vectors ----

type vectorFile struct {
	Spec       string                   `json:"spec"`
	Note       string                   `json:"note"`
	Keys       []vectorKey              `json:"keys"` // the pinned set; tokens are signed with keys[0] unless noted
	Verifier   vectorVerifier           `json:"verifier"`
	Identities map[string]auth.Identity `json:"identities"`
	Actions    map[string]model.Action  `json:"actions"`
	Payloads   []payloadVector          `json:"payloads"`
	Tokens     []tokenVector            `json:"tokens"`
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

// presentation is one Verify call: the action about to be signed and the
// authenticated identity of the request it came from.
type presentation struct {
	Action   string `json:"action"`
	Identity string `json:"identity"`
	Now      int64  `json:"now"`
	Want     string `json:"want"`
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

func vecKey(label string) (vectorKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return vectorKey{SeedHex: fmt.Sprintf("%x", seed), PublicB64: b64.EncodeToString(pub), Kid: Kid(pub)}, priv
}

func buildVectors(t *testing.T) vectorFile {
	vk, priv := vecKey("stopbar decision-token-v2 test key")
	vk2, priv2 := vecKey("stopbar decision-token-v2 second pinned key") // e.g. a retired key
	_, other := vecKey("stopbar decision-token-v2 unpinned key")
	pub := priv.Public().(ed25519.PublicKey)
	k := vk.Kid

	evm := loadActionFixture(t, "../../spec/fixtures/action_request.evm_tx.json")
	tool := loadActionFixture(t, "../../spec/fixtures/action_request.tool_call.json")
	evmMixed := evm
	evmMixed.Data = "0x" + strings.ToUpper(evm.Data[2:]) // same bytes, upper-case hex
	evmMixed.ValueWei = "000"                            // same value, non-canonical form
	evmOtherTo := evm
	evmOtherTo.To = "0x9f30000000000000000000000000000000000c21"
	evmOtherValue := evm
	evmOtherValue.ValueWei = "1"
	evmOtherFee := evm // same tx, fee raised after the decision
	evmOtherFee.MaxFeePerGas = "900000000000000"
	evmOtherGas := evm
	evmOtherGas.GasLimit = "30000000"
	evmOtherTxNonce := evm
	evmOtherTxNonce.TxNonce = "1"
	const typedPath = "../../spec/fixtures/action_request.evm_typed_data.json"
	typed := loadActionFixture(t, typedPath)
	typedOtherAmount := loadActionFixture(t, typedPath) // amount raised to the Permit2 max after the decision
	typedOtherAmount.TypedData.Message["details"].(map[string]any)["amount"] = "1461501637330902918203684832716283019655932542975"
	typedOtherSpender := loadActionFixture(t, typedPath)
	typedOtherSpender.TypedData.Message["spender"] = "0x9f30000000000000000000000000000000000c21"
	personal := loadActionFixture(t, "../../spec/fixtures/action_request.evm_personal_sign.json")
	personalMixed := personal
	personalMixed.Message = "0x" + strings.ToUpper(personal.Message[2:]) // same bytes, upper-case hex
	personalOther := personal
	personalOther.Message = personal.Message + "00"
	actions := map[string]model.Action{
		"evm": evm, "evm_noncanonical_input": evmMixed, "evm_other_to": evmOtherTo,
		"evm_other_value": evmOtherValue, "evm_other_fee": evmOtherFee, "evm_other_gas": evmOtherGas,
		"evm_other_tx_nonce": evmOtherTxNonce, "tool_call": tool,
		"typed_data": typed, "typed_data_other_amount": typedOtherAmount, "typed_data_other_spender": typedOtherSpender,
		"personal_sign": personal, "personal_sign_noncanonical_input": personalMixed, "personal_sign_other_message": personalOther,
	}
	requester := auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", AgentID: "trading-bot-1", KeyID: "ak_01"}
	with := func(f func(*auth.Identity)) auth.Identity { id := requester; f(&id); return id }
	identities := map[string]auth.Identity{
		"requester":       requester,
		"other_key":       with(func(id *auth.Identity) { id.KeyID = "ak_02" }),
		"other_agent":     with(func(id *auth.Identity) { id.AgentID = "trading-bot-2" }),
		"other_method":    with(func(id *auth.Identity) { id.Method = auth.MethodMTLS }),
		"other_tenant":    with(func(id *auth.Identity) { id.Tenant = "other" }),
		"no_agent":        with(func(id *auth.Identity) { id.AgentID = "" }),
		"unauthenticated": {},
	}

	vf := vectorFile{
		Spec: "decision-token-v2",
		Note: "Generated by internal/decision/token_v2_test.go. Each token is presented to a fresh verifier pinning every key in 'keys', in order; " +
			"'identity' names the authenticated identity of the request being signed; 'want' is OK or an error code from spec §4.",
		Keys:       []vectorKey{vk, vk2},
		Verifier:   vectorVerifier{Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme"},
		Identities: identities,
		Actions:    actions,
	}
	names := make([]string, 0, len(actions))
	for n := range actions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c, err := CanonicalAction(actions[n])
		if err != nil {
			t.Fatal(err)
		}
		vf.Payloads = append(vf.Payloads, payloadVector{Action: n, Canonical: string(c), PayloadHash: canon.Digest(c)})
	}

	iat := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC).Unix()
	now := iat + 10
	base := func(a model.Action) Claims {
		ph, err := PayloadHash(a)
		if err != nil {
			t.Fatal(err)
		}
		return Claims{
			V: TokenVersion, Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme",
			RequestID: "req_01JD0000000000000000000001", Nonce: "Zml4dHVyZS1ub25jZS0wMDAx",
			Outcome: model.Allow, PayloadHash: ph,
			PolicyBundleHash: "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			ReservationID:    ptr("rsv_01JD0000000000000000000001"),
			Iat:              iat, Exp: iat + 60,
			AuthMethod: string(auth.MethodAPIKey), KeyID: "ak_01", AgentID: "trading-bot-1",
		}
	}
	sign := func(c Claims) string { return signRaw(priv, mustCanon(t, header(k)), mustCanon(t, c)) }
	claims := func(f func(*Claims)) string { c := base(evm); f(&c); return sign(c) }
	once := func(action string, want string) []presentation {
		return []presentation{{Action: action, Identity: "requester", Now: now, Want: want}}
	}
	as := func(identity, want string) []presentation {
		return []presentation{{Action: "evm", Identity: identity, Now: now, Want: want}}
	}
	add := func(name, tok string, ps []presentation) {
		vf.Tokens = append(vf.Tokens, tokenVector{Name: name, Token: tok, Presentations: ps})
	}

	good := sign(base(evm))
	toolClaims := base(tool)
	toolClaims.RequestID, toolClaims.Nonce, toolClaims.ReservationID = "req_01JD0000000000000000000002", "dG9vbC1jYWxsLW5vbmNlLTAy", nil
	unauth := claims(func(c *Claims) { c.AuthMethod, c.KeyID, c.AgentID = string(auth.MethodNone), "", "" })
	add("allow_evm", good, once("evm", "OK"))
	add("allow_evm_noncanonical_input", good, once("evm_noncanonical_input", "OK"))
	add("allow_tool_call", sign(toolClaims), once("tool_call", "OK"))
	typedTok, personalTok := sign(base(typed)), sign(base(personal))
	add("allow_typed_data", typedTok, once("typed_data", "OK"))
	add("payload_mismatch_typed_data_amount", typedTok, once("typed_data_other_amount", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_typed_data_spender", typedTok, once("typed_data_other_spender", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_typed_data_as_tx", typedTok, once("evm", "PAYLOAD_MISMATCH"))
	add("allow_personal_sign", personalTok, once("personal_sign", "OK"))
	add("allow_personal_sign_noncanonical_input", personalTok, once("personal_sign_noncanonical_input", "OK"))
	add("payload_mismatch_personal_sign_message", personalTok, once("personal_sign_other_message", "PAYLOAD_MISMATCH"))
	add("allow_unauthenticated", unauth, as("unauthenticated", "OK"))
	add("allow_mtls", claims(func(c *Claims) { c.AuthMethod = string(auth.MethodMTLS) }), as("other_method", "OK"))
	add("allow_no_agent", claims(func(c *Claims) { c.AgentID = "" }), as("no_agent", "OK"))
	add("allow_signed_by_second_pinned_key", signRaw(priv2, mustCanon(t, header(vk2.Kid)), mustCanon(t, base(evm))), once("evm", "OK"))
	add("replay", good, []presentation{{"evm", "requester", now, "OK"}, {"evm", "requester", now + 1, "REPLAYED"}})
	add("failed_check_does_not_consume_nonce", good, []presentation{{"evm_other_to", "requester", now, "PAYLOAD_MISMATCH"}, {"evm", "requester", now, "OK"}})
	add("failed_identity_does_not_consume_nonce", good, []presentation{{"evm", "other_key", now, "WRONG_IDENTITY"}, {"evm", "requester", now, "OK"}})
	add("payload_mismatch_to", good, once("evm_other_to", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_value", good, once("evm_other_value", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_kind", good, once("tool_call", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_fee", good, once("evm_other_fee", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_gas", good, once("evm_other_gas", "PAYLOAD_MISMATCH"))
	add("payload_mismatch_tx_nonce", good, once("evm_other_tx_nonce", "PAYLOAD_MISMATCH"))
	add("identity_wrong_key", good, as("other_key", "WRONG_IDENTITY"))
	add("identity_wrong_agent", good, as("other_agent", "WRONG_IDENTITY"))
	add("identity_wrong_method", good, as("other_method", "WRONG_IDENTITY"))
	add("identity_wrong_tenant", good, as("other_tenant", "WRONG_IDENTITY"))
	add("identity_authenticated_token_unauthenticated_request", good, as("unauthenticated", "WRONG_IDENTITY"))
	add("identity_unauthenticated_token_authenticated_request", unauth, as("requester", "WRONG_IDENTITY"))
	add("outcome_deny", claims(func(c *Claims) { c.Outcome = model.Deny }), once("evm", "NOT_ALLOWED"))
	add("outcome_escalate", claims(func(c *Claims) { c.Outcome = model.Escalate }), once("evm", "NOT_ALLOWED"))
	add("expired_at_exp", good, []presentation{{"evm", "requester", iat + 60, "EXPIRED"}})
	add("valid_just_before_exp", good, []presentation{{"evm", "requester", iat + 59, "OK"}})
	add("not_yet_valid", good, []presentation{{"evm", "requester", iat - clockSkew - 1, "NOT_YET_VALID"}})
	add("within_clock_skew", good, []presentation{{"evm", "requester", iat - clockSkew, "OK"}})
	add("ttl_too_long", claims(func(c *Claims) { c.Exp = c.Iat + MaxTTL + 1 }), once("evm", "TTL_INVALID"))
	add("exp_before_iat", claims(func(c *Claims) { c.Exp = c.Iat }), once("evm", "TTL_INVALID"))
	add("wrong_issuer", claims(func(c *Claims) { c.Iss = "stopbar:other" }), once("evm", "WRONG_ISSUER"))
	add("wrong_audience", claims(func(c *Claims) { c.Aud = "signer:other" }), once("evm", "WRONG_AUDIENCE"))
	add("wrong_tenant", claims(func(c *Claims) { c.Tenant = "other" }), once("evm", "WRONG_TENANT"))
	add("bad_version_1", claims(func(c *Claims) { c.V = 1 }), once("evm", "BAD_VERSION"))
	add("bad_version_3", claims(func(c *Claims) { c.V = 3 }), once("evm", "BAD_VERSION"))
	add("bad_claims_unknown_auth_method", claims(func(c *Claims) { c.AuthMethod = "password" }), once("evm", "BAD_CLAIMS"))
	add("bad_claims_authenticated_without_key_id", claims(func(c *Claims) { c.KeyID = "" }), once("evm", "BAD_CLAIMS"))
	add("bad_claims_unauthenticated_with_key_id", claims(func(c *Claims) { c.AuthMethod = string(auth.MethodNone) }), as("unauthenticated", "BAD_CLAIMS"))

	// v1 tokens: a genuine v1 token (v1 typ, v1's twelve claims) signed with a
	// pinned key; v1 claims under the v2 typ.
	var v1 map[string]any
	if err := json.Unmarshal(mustCanon(t, base(evm)), &v1); err != nil {
		t.Fatal(err)
	}
	delete(v1, "auth_method")
	delete(v1, "key_id")
	delete(v1, "agent_id")
	v1["v"] = 1
	v1Hdr := mustCanon(t, map[string]string{"alg": "EdDSA", "kid": k, "typ": v1TokenType})
	add("v1_token", signRaw(priv, v1Hdr, mustCanon(t, v1)), once("evm", "BAD_HEADER"))
	add("v1_claims_under_v2_header", signRaw(priv, mustCanon(t, header(k)), mustCanon(t, v1)), once("evm", "BAD_CLAIMS"))
	add("v2_claims_under_v1_header", signRaw(priv, v1Hdr, mustCanon(t, base(evm))), once("evm", "BAD_HEADER"))

	add("unknown_kid", signRaw(other, mustCanon(t, header(Kid(other.Public().(ed25519.PublicKey)))), mustCanon(t, base(evm))), once("evm", "UNKNOWN_KEY"))
	add("pinned_kid_wrong_key", signRaw(other, mustCanon(t, header(k)), mustCanon(t, base(evm))), once("evm", "BAD_SIGNATURE"))
	gp := strings.Split(good, ".")
	swapped := b64.EncodeToString(mustCanon(t, header(vk2.Kid))) + "." + gp[1] + "." + gp[2] // signed by keys[0], kid says keys[1]
	add("kid_swapped_to_other_pinned_key", swapped, once("evm", "BAD_SIGNATURE"))
	denied := base(evm)
	denied.Outcome = model.Deny
	dp := strings.Split(sign(denied), ".")
	add("payload_swapped_under_signature", dp[0]+"."+gp[1]+"."+dp[2], once("evm", "BAD_SIGNATURE"))
	otherID := base(evm)
	otherID.KeyID = "ak_02"
	ip := strings.Split(sign(otherID), ".")
	add("identity_swapped_under_signature", gp[0]+"."+ip[1]+"."+gp[2], as("other_key", "BAD_SIGNATURE"))

	payload := mustCanon(t, base(evm))
	noneHdr := mustCanon(t, map[string]string{"alg": "none", "kid": k, "typ": TokenType})
	add("alg_none", b64.EncodeToString(noneHdr)+"."+b64.EncodeToString(payload)+".", once("evm", "BAD_HEADER"))
	add("alg_none_signed", signRaw(priv, noneHdr, payload), once("evm", "BAD_HEADER"))
	hsHdr := mustCanon(t, map[string]string{"alg": "HS256", "kid": k, "typ": TokenType})
	hsIn := b64.EncodeToString(hsHdr) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, pub) // classic alg confusion: public key as HMAC secret
	mac.Write([]byte(hsIn))
	add("alg_hs256_confusion", hsIn+"."+b64.EncodeToString(mac.Sum(nil)), once("evm", "BAD_HEADER"))
	jku := mustCanon(t, map[string]string{"alg": "EdDSA", "jku": "https://attacker.example/jwks", "kid": k, "typ": TokenType})
	add("header_extra_member", signRaw(priv, jku, payload), once("evm", "BAD_HEADER"))
	crit := mustCanon(t, map[string]any{"alg": "EdDSA", "crit": []string{"exp"}, "kid": k, "typ": TokenType})
	add("header_crit", signRaw(priv, crit, payload), once("evm", "BAD_HEADER"))
	add("header_wrong_typ", signRaw(priv, mustCanon(t, map[string]string{"alg": "EdDSA", "kid": k, "typ": "JWT"}), payload), once("evm", "BAD_HEADER"))
	add("header_non_canonical", signRaw(priv, []byte(`{"typ":"`+TokenType+`","alg":"EdDSA","kid":"`+k+`"}`), payload), once("evm", "BAD_HEADER"))

	add("payload_whitespace", signRaw(priv, mustCanon(t, header(k)), append([]byte(" "), payload...)), once("evm", "NON_CANONICAL"))
	dup := bytes.Replace(payload, []byte(`{"agent_id"`), []byte(`{"agent_id":"x","agent_id"`), 1)
	add("payload_duplicate_member", signRaw(priv, mustCanon(t, header(k)), dup), once("evm", "NON_CANONICAL"))
	var extra map[string]any
	if err := json.Unmarshal(payload, &extra); err != nil {
		t.Fatal(err)
	}
	extra["admin"] = true
	add("unknown_claim", signRaw(priv, mustCanon(t, header(k)), mustCanon(t, extra)), once("evm", "BAD_CLAIMS"))
	delete(extra, "admin")
	delete(extra, "key_id")
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
	checkPayloads(t, file.Actions, file.Payloads)
	pinned := map[string]ed25519.PublicKey{}
	for _, k := range file.Keys {
		pub, err := b64.DecodeString(k.PublicB64)
		if err != nil || Kid(pub) != k.Kid {
			t.Fatalf("key/kid mismatch")
		}
		pinned[k.Kid] = pub
	}
	for _, tv := range file.Tokens {
		var now int64
		v := &Verifier{
			Keys: func() map[string]ed25519.PublicKey { return pinned },
			Iss:  file.Verifier.Iss, Aud: file.Verifier.Aud, Tenant: file.Verifier.Tenant,
			Spent: mapSpent{}, Clock: func() time.Time { return time.Unix(now, 0) },
		}
		for i, p := range tv.Presentations {
			now = p.Now
			id, ok := file.Identities[p.Identity]
			if !ok {
				t.Fatalf("%s[%d]: unknown identity %q", tv.Name, i, p.Identity)
			}
			if res := verifyCode(t, v, tv.Token, file.Actions[p.Action], id); res != p.Want {
				t.Errorf("%s[%d]: got %s, want %s", tv.Name, i, res, p.Want)
			}
		}
	}
}

// The frozen v1 vectors still describe the payload binding (unchanged in v2),
// but no v1 token verifies any more: a v1-only verifier stays v1, and this
// one accepts v2 only, whatever identity is presented.
func TestFrozenV1VectorsRejected(t *testing.T) {
	b, err := os.ReadFile(v1VectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Key      vectorKey               `json:"key"`
		Verifier vectorVerifier          `json:"verifier"`
		Actions  map[string]model.Action `json:"actions"`
		Payloads []payloadVector         `json:"payloads"`
		Tokens   []struct {
			Name          string `json:"name"`
			Token         string `json:"token"`
			Presentations []struct {
				Action string `json:"action"`
				Now    int64  `json:"now"`
			} `json:"presentations"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	checkPayloads(t, file.Actions, file.Payloads)
	pub, err := b64.DecodeString(file.Key.PublicB64)
	if err != nil {
		t.Fatal(err)
	}
	ids := []auth.Identity{{}, {Method: auth.MethodAPIKey, Tenant: file.Verifier.Tenant, KeyID: "ak_01"}}
	for _, tv := range file.Tokens {
		for _, id := range ids {
			for _, p := range tv.Presentations {
				v := &Verifier{
					Keys: func() map[string]ed25519.PublicKey { return map[string]ed25519.PublicKey{file.Key.Kid: pub} },
					Iss:  file.Verifier.Iss, Aud: file.Verifier.Aud, Tenant: file.Verifier.Tenant,
					Spent: mapSpent{}, Clock: func() time.Time { return time.Unix(p.Now, 0) },
				}
				if res := verifyCode(t, v, tv.Token, file.Actions[p.Action], id); res == "OK" {
					t.Errorf("v1 token %s verified under v2", tv.Name)
				}
			}
		}
	}
}

func checkPayloads(t *testing.T, actions map[string]model.Action, payloads []payloadVector) {
	t.Helper()
	for _, p := range payloads {
		c, err := CanonicalAction(actions[p.Action])
		if err != nil || string(c) != p.Canonical || canon.Digest(c) != p.PayloadHash {
			t.Errorf("payload %s: canonical/hash mismatch (%v)", p.Action, err)
		}
	}
}

func verifyCode(t *testing.T, v *Verifier, tok string, a model.Action, id auth.Identity) string {
	t.Helper()
	if _, err := v.Verify(tok, a, id); err != nil {
		var ve *VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("untyped error %v", err)
		}
		return ve.Code
	}
	return "OK"
}

func TestPayloadHashRejectsUnbindable(t *testing.T) {
	big := uint64(maxSafeInt)
	for name, a := range map[string]model.Action{
		"withdrawal":        {Kind: model.KindWithdrawal},
		"evm no chain":      {Kind: model.KindEVMTx, ValueWei: "0"},
		"evm no to":         {Kind: model.KindEVMTx, ChainID: ptr(uint64(1)), ValueWei: "0"},
		"evm chain >= 2^53": {Kind: model.KindEVMTx, ChainID: &big, ValueWei: "0"},
		"evm negative":      {Kind: model.KindEVMTx, ChainID: ptr(uint64(1)), ValueWei: "-1"},
		"evm hex value":     {Kind: model.KindEVMTx, ChainID: ptr(uint64(1)), ValueWei: "0x10"},
		"tool no name":      {Kind: model.KindToolCall},
		"typed no chain":    {Kind: model.KindEVMTypedData, TypedData: &model.TypedData{}},
		"typed no data":     {Kind: model.KindEVMTypedData, ChainID: ptr(uint64(1))},
		"personal no msg":   {Kind: model.KindEVMPersonalSign, ChainID: ptr(uint64(1))},
		"personal raw text": {Kind: model.KindEVMPersonalSign, ChainID: ptr(uint64(1)), Message: "hello"},
	} {
		if _, err := PayloadHash(a); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// ---- production signer, rotation, key files ----

func evmFixtureRequest(t *testing.T) model.ActionRequest {
	t.Helper()
	b, err := os.ReadFile("../../spec/fixtures/action_request.evm_tx.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.ActionRequest
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func allowFor(t *testing.T, r model.ActionRequest, at time.Time) model.Decision {
	t.Helper()
	ph, err := PayloadHash(r.Action)
	if err != nil {
		t.Fatal(err)
	}
	return model.Decision{RequestID: r.ID, Outcome: model.Allow, PayloadHash: ph,
		PolicyBundleHash: "sha256:" + strings.Repeat("a", 64), IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
}

func TestSignerRoundTripAndRotation(t *testing.T) {
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	ring := NewKeyRing(k1)
	s := &Signer{Keys: ring, Iss: "stopbar:test", Aud: "signer:local-1"}
	r := evmFixtureRequest(t)
	now := time.Now()
	v := &Verifier{Keys: ring.PublicKeys, Iss: "stopbar:test", Aud: "signer:local-1", Tenant: r.Tenant, Spent: mapSpent{}}
	id := auth.Identity{Method: auth.MethodAPIKey, Tenant: r.Tenant, AgentID: r.Actor.AgentID, KeyID: "ak_01", Scopes: []string{"evaluate"}}

	old, err := s.Sign(context.Background(), id, r, allowFor(t, r, now))
	if err != nil {
		t.Fatal(err)
	}
	ring.Rotate(k2)
	r2 := r
	r2.Nonce = "another-nonce-0001"
	fresh, err := s.Sign(context.Background(), id, r2, allowFor(t, r2, now))
	if err != nil {
		t.Fatal(err)
	}
	// Old keys verify; only the new key signs.
	if _, err := v.Verify(old, r.Action, id); err != nil {
		t.Fatalf("token from retired key: %v", err)
	}
	if _, err := v.Verify(fresh, r2.Action, id); err != nil {
		t.Fatalf("token from active key: %v", err)
	}
	if ring.ActiveKid() != Kid(k2.Public().(ed25519.PublicKey)) {
		t.Fatal("rotation did not switch the signing key")
	}
	jwks := ring.JWKS()
	if len(jwks) != 2 || jwks[0].Status != "active" || jwks[1].Status != "retired" || jwks[1].Kid != Kid(k1.Public().(ed25519.PublicKey)) {
		t.Fatalf("jwks %+v", jwks)
	}
	// Single use: the same token never verifies twice.
	if _, err := v.Verify(old, r.Action, id); err == nil || err.(*VerifyError).Code != "REPLAYED" {
		t.Fatalf("replay: %v", err)
	}
}

// The signer binds the identity auth established, and refuses one that is
// malformed or whose tenant is not the request's.
func TestSignerBindsIdentity(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(nil)
	s := &Signer{Keys: NewKeyRing(k), Iss: "stopbar:test", Aud: "signer:local-1"}
	r := evmFixtureRequest(t)
	d := allowFor(t, r, time.Now())
	claimsOf := func(tok string) Claims {
		var c Claims
		if err := json.Unmarshal(mustB64(t, strings.Split(tok, ".")[1]), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	id := auth.Identity{Method: auth.MethodMTLS, Tenant: r.Tenant, AgentID: "agent-from-auth", KeyID: "spiffe://acme/bot"}
	tok, err := s.Sign(context.Background(), id, r, d)
	if c := claimsOf(tok); err != nil || c.V != 2 || c.AuthMethod != "mtls" || c.KeyID != id.KeyID || c.AgentID != id.AgentID {
		t.Fatalf("authenticated: %+v %v", c, err)
	}
	tok, err = s.Sign(context.Background(), auth.Identity{}, r, d)
	if c := claimsOf(tok); err != nil || c.AuthMethod != "none" || c.KeyID != "" || c.AgentID != "" {
		t.Fatalf("unauthenticated (the body's agent %q must not be bound): %+v %v", r.Actor.AgentID, c, err)
	}
	for name, bad := range map[string]auth.Identity{
		"other tenant":        {Method: auth.MethodAPIKey, Tenant: "other", KeyID: "ak_01"},
		"no key id":           {Method: auth.MethodAPIKey, Tenant: r.Tenant},
		"unknown method":      {Method: "password", Tenant: r.Tenant, KeyID: "ak_01"},
		"none with key":       {Method: auth.MethodNone, KeyID: "ak_01"},
		"empty with an agent": {AgentID: "a"},
	} {
		if _, err := s.Sign(context.Background(), bad, r, d); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeyFileGuards(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	good := filepath.Join(dir, "decision.key")
	if err := WriteKeyFile(good, priv); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadKeyFile(good); err != nil || !got.Equal(priv) {
		t.Fatalf("round trip: %v", err)
	}
	if err := os.Chmod(good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(good); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	wallet := filepath.Join(dir, "wallet.key") // e.g. a hex secp256k1 key
	if err := os.WriteFile(wallet, []byte("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(wallet); err == nil {
		t.Fatal("a wallet key file loaded as a decision key")
	}
}
