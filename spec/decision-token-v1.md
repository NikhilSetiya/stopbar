# Decision token — v1

Status: draft (CS-008). Amended in CS-161 to bind every transaction field (§2.1, §2.3). No verifier outside this repository existed, so the version stays at v1, and the vectors were regenerated.

**Freeze rule:** this spec freezes at the first tagged release (v0.1.0-alpha). After that, *any* change to the header, the claims, the canonical action or the verification order bumps `v` and `typ`, and both versions are specified side by side. A frozen version is never amended in place. Test vectors: [`vectors/decision-token-v1.json`](vectors/decision-token-v1.json),
generated and checked by `internal/decision/token_v1_test.go`.

A decision token is Stopbar's signed statement that one specific action may be
signed, once, before a deadline. In gatekeeper mode the signer adapter refuses
to sign anything without one (LLD §10.1, FR-INT-3). The token is the
**only** thing a signer adapter trusts. It never trusts the requester, the
transport or the response body around the token.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Design choices

| Choice | Why |
|---|---|
| JWS compact serialisation, Ed25519 (`EdDSA`, RFC 8037) | Ubiquitous verifiers and deterministic signatures, so vectors are byte-exact. In Go it's `crypto/ed25519`, which keeps the trusted core stdlib-only. |
| Header and payload are RFC 8785 (JCS) canonical JSON | Same bytes on every implementation and no duplicate-member ambiguity. Reuses `internal/canon`. |
| Closed header and claim sets | Unknown members are rejected, not ignored. This removes `jku`/`jwk`/`x5u`/`crit` key-injection and "extra claim means something to someone" bugs. |
| `payload_hash` is sha256 over a canonical action, not a chain-native tx hash | It's stdlib-only, it works for tool calls too, and it hashes before gas and nonce are chosen (see §2.3). Keccak and EIP-712 belong to co-signer mode (LLD §10.2, Phase 4). |
| Integer `iat`/`exp` (seconds) | NumericDate per RFC 7519. Keeps JCS number handling trivial. |

## 2. Payload binding

```
payload_hash = "sha256:" + hex( SHA-256( JCS( canonical_action ) ) )
```

The action MUST first pass `ActionRequest` validation (`internal/model`).
`canonical_action` is then built from `action`, keeping only the fields below.
Any other field, including the whole request envelope, is outside the binding.

### 2.1 `evm_tx`

The requester sends the **complete unsigned transaction**. Every field is bound, and the signer adapter fills in nothing after the decision: any field filled in later would be a field policy never saw. Only EIP-1559 (`tx_type` 2) transactions with no access list are supported in v1.

```json
{"v": 1, "kind": "evm_tx", "tx_type": 2, "chain_id": 8453,
 "from": "0x…", "to": "0x…", "value_wei": "0", "data": "0x…",
 "tx_nonce": "7", "gas_limit": "100000",
 "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000"}
```

- `from`, `to` and `data` are lower-cased. The hex digits and the `0x` prefix are both lower-case, so EIP-55 checksummed and upper-case input bind the same way. Empty calldata is `"0x"`, whether sent as `""` or `"0x"`.
- `value_wei`, `tx_nonce`, `gas_limit`, `max_fee_per_gas` and `max_priority_fee_per_gas` are re-serialised as base-10 integers with no sign and no leading zeros (`"000"` becomes `"0"`). Negative or non-decimal values are an error. These are strings, so values beyond 2^53 survive.
- `chain_id` MUST be in `[1, 2^53)`, since JCS numbers are IEEE-754 doubles.
- Contract creation (no `to`), legacy and EIP-2930 transactions, and access lists have no binding in v1, so no token can be issued for them.

### 2.2 `tool_call`

```json
{"v": 1, "kind": "tool_call", "tool": "crm.export_contacts", "args": {…}}
```

- `args` is hashed as JCS of the JSON value as received. A missing or null `args` becomes `{}`.
- Numbers inside `args` are JCS doubles. Integers beyond ±2^53 MUST be sent as strings. The gateway MUST reject requests whose numbers don't round-trip (CS-101).

### 2.3 Nothing is left unbound

Earlier drafts left nonce, gas and fees for the adapter to choose. That let an
approved transaction differ from the one signed. It also hid the fee from
policy: a zero-value transaction with an absurd `gas_limit × max_fee_per_gas`
burns ETH while passing every value cap (corpus `CS-2026-0007`). Now all of
them are bound, so the adapter MUST sign the transaction byte-for-byte as
approved. The engine also counts `gas_limit × max_fee_per_gas`, priced, as
spend against USD caps, and the decoder flags `excessive_fee`.

`withdrawal` has no binding in v1. The engine MUST NOT issue tokens for it, and
any request of that kind fails closed.

## 3. Token

`BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)` uses
unpadded base64url (RFC 7515). The signature is Ed25519 over the ASCII bytes of
the first two segments joined by `"."`.

### 3.1 Header

Exactly these three members, JCS-canonical:

```json
{"alg":"EdDSA","kid":"<RFC 7638 thumbprint>","typ":"stopbar-decision+jws"}
```

`kid` is the RFC 7638 JWK thumbprint (base64url SHA-256 of
`{"crv":"Ed25519","kty":"OKP","x":"<pub>"}`). It names a key the verifier
already has. It never brings a new one.

### 3.2 Claims

Exactly these twelve members, JCS-canonical:

| Claim | Type | Meaning |
|---|---|---|
| `v` | int | Always `1`. |
| `iss` | string | Stopbar deployment ID (e.g. `stopbar:prod-eu1`). |
| `aud` | string | Signer adapter ID this token is for (e.g. `signer:local-1`). |
| `tenant` | string | `ActionRequest.tenant`. |
| `request_id` | string | `ActionRequest.id`, which joins the token to its audit record. |
| `nonce` | string | `ActionRequest.nonce`, the single-use key (§4 step 11). |
| `outcome` | string | `allow`, `deny` or `escalate`. Tokens can be issued for any outcome so advisory clients can verify a denial, but only `allow` authorises signing. |
| `payload_hash` | string | §2. |
| `policy_bundle_hash` | string | `sha256:…` of the active bundle (LLD §5.4). |
| `reservation_id` | string \| null | Limiter reservation to commit after broadcast. |
| `iat` | int | Issued at, Unix seconds. |
| `exp` | int | Expiry, Unix seconds. `0 < exp − iat ≤ 300`, with a default of 60. |

An escalated request that is later approved gets a **new** `allow` token, with
the same `request_id` and `nonce` and a fresh `iat`/`exp`. The approvals
themselves are in the audit log, not the token.

## 4. Verification

A verifier is configured with a **pinned** key set (`kid` → public key,
distributed via `/v1/keys` out of band and never fetched from a token), its own
`aud`, the expected `iss` and `tenant`, a clock, and a replay store. It MUST
run these steps in order and stop at the first failure. Every failure means
**do not sign**.

| # | Check | Error code |
|---|---|---|
| 0 | Exactly three segments, each strict unpadded base64url | `MALFORMED` |
| 1 | Header is JCS-canonical, has exactly `{alg, kid, typ}`, `alg` = `EdDSA` and `typ` = `stopbar-decision+jws` | `BAD_HEADER` |
| 2 | `kid` is in the pinned key set | `UNKNOWN_KEY` |
| 3 | The signature is 64 bytes and verifies. **No claim is read before this step.** | `BAD_SIGNATURE` |
| 4 | Payload is JCS-canonical (this also rejects duplicate members) | `NON_CANONICAL` |
| 5 | Exactly the twelve claims of §3.2, each of the right type | `BAD_CLAIMS` |
| 6 | `v` = 1 | `BAD_VERSION` |
| 7 | `iss`, `aud` and `tenant` equal the verifier's own values | `WRONG_ISSUER` / `WRONG_AUDIENCE` / `WRONG_TENANT` |
| 8a | `0 < exp − iat ≤ 300` | `TTL_INVALID` |
| 8b | `iat ≤ now + 5s` (clock skew) | `NOT_YET_VALID` |
| 8c | `now < exp` (`exp` is exclusive, with no skew) | `EXPIRED` |
| 9 | `outcome` = `allow` | `NOT_ALLOWED` |
| 10 | `payload_hash` equals §2 recomputed **from the transaction or call the adapter is about to sign**, never from a value the requester supplied alongside the token. A swap of any field (to, value, calldata, nonce, gas, fees, chain) fails here | `PAYLOAD_MISMATCH` |
| 11 | `(iss, tenant, nonce)` has not been accepted before. Record it until `exp` only after steps 0–10 pass, so a failed attempt never burns the nonce. | `REPLAYED` |

The replay store MUST be durable across adapter restarts for at least the
maximum TTL (300 s). Without that, a restart opens a replay window.

## 5. Threats addressed

| Threat (HLD §8) | Defence |
|---|---|
| Reusing a decision token | Step 11 (single use) and step 8 (≤ 300 s lifetime) |
| Token for tx A used to sign tx B | Step 10. The adapter hashes what it signs. |
| Token for adapter or tenant X used at Y | Steps 7 (`aud`, `tenant`) |
| `alg: none`, HS256 with the public key as the secret, `jku`/`jwk` key injection | Steps 1–2 (fixed `alg`, closed header, pinned keys) |
| Changing claims under a valid signature | Step 3 runs before any claim is read |
| Parser differentials (whitespace, key order, duplicate members) | Steps 1 and 4 (canonical bytes only) |
| Deny or escalate token presented as permission | Step 9 |

## 6. Versioning

Any change to the header, the claims, the canonical action or the verification
order bumps `v` and the `typ`. Verifiers reject versions they don't know.
