# Decision token — v2

Status: draft (CS-103, increment 2). Supersedes [`decision-token-v1.md`](decision-token-v1.md), which is frozen and unchanged. Stopbar issues v2 only, and its verifier and gatekeeper adapter accept v2 only. Decision: [ADR 0003](../docs/adr/0003-decision-token-v2-identity.md).

**What changed from v1:** the token also binds the **authenticated requester identity** (§3.3): how the request was authenticated, the credential's key ID and its agent. That identity comes from authentication (`internal/auth`), never from the request body. A verifier checks it against the authenticated identity of the request whose transaction it is about to sign (§4 step 7d). The header `typ` and the claim `v` are bumped, so neither version can be read as the other. The payload binding (§2) is unchanged.

**Freeze rule:** as for v1. This spec freezes at the first tagged release that issues it. After that, *any* change to the header, the claims, the canonical action or the verification order bumps `v` and `typ`, and both versions are specified side by side. Test vectors: [`vectors/decision-token-v2.json`](vectors/decision-token-v2.json), generated and checked by `internal/decision/token_v2_test.go`, which also checks that no token in the frozen v1 vectors verifies.

A decision token is Stopbar's signed statement that one specific action, requested by one specific authenticated caller, may be signed, once, before a deadline. In gatekeeper mode the signer adapter refuses to sign anything without one (LLD §10.1, FR-INT-3). The token is the **only** thing a signer adapter trusts about the decision. It never trusts the requester, the transport or the response body around the token.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Design choices

v1 §1 applies unchanged (Ed25519 compact JWS, JCS-canonical header and payload, closed header and claim sets, sha256 `payload_hash`, integer `iat`/`exp`). In addition:

| Choice | Why |
|---|---|
| Bind the authenticated identity, not the body's `actor` | The body is the requester's claim. Since CS-103 the gateway rejects a body whose `tenant`/`actor.agent_id` disagree with the credential, and v2 carries the credential's identity into the signed statement, so a token minted for one caller is useless to any other. |
| Flat identity claims (`auth_method`, `key_id`, `agent_id`) | Strings only, so the closed-set and type checks stay as simple as v1's. |
| Unauthenticated is explicit (`auth_method` = `none`) | With auth off (loopback dev only) a token still names who asked: nobody authenticated. A verifier holding an authenticated request refuses it, and vice versa. |
| New `typ`, not only a new `v` | A v1-only verifier rejects a v2 token at step 1, and a v2 verifier rejects a v1 token at step 1, before any claim is read. |

## 2. Payload binding

Identical to [v1 §2](decision-token-v1.md#2-payload-binding), including the canonical action's own `"v": 1`:

```
payload_hash = "sha256:" + hex( SHA-256( JCS( canonical_action ) ) )
```

`evm_tx` (complete unsigned EIP-1559 transaction, every field bound) and `tool_call` are bound exactly as in v1 §2.1–2.3. `withdrawal`, contract creation, legacy and EIP-2930 transactions and access lists have no binding, and no token can be issued for them.

## 3. Token

`BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)` uses unpadded base64url (RFC 7515). The signature is Ed25519 over the ASCII bytes of the first two segments joined by `"."`.

### 3.1 Header

Exactly these three members, JCS-canonical:

```json
{"alg":"EdDSA","kid":"<RFC 7638 thumbprint>","typ":"stopbar-decision-v2+jws"}
```

`kid` is the RFC 7638 JWK thumbprint (base64url SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"<pub>"}`). It names a key the verifier already has. It never brings a new one.

### 3.2 Claims

Exactly these fifteen members, JCS-canonical:

| Claim | Type | Meaning |
|---|---|---|
| `v` | int | Always `2`. |
| `iss` | string | Stopbar deployment ID (e.g. `stopbar:prod-eu1`). |
| `aud` | string | Signer adapter ID this token is for (e.g. `signer:local-1`). |
| `tenant` | string | `ActionRequest.tenant`. When the request was authenticated it equals the identity's tenant (the gateway rejects a mismatch, and the signer refuses to issue one). |
| `request_id` | string | `ActionRequest.id`, which joins the token to its audit record. |
| `nonce` | string | `ActionRequest.nonce`, the single-use key (§4 step 11). |
| `outcome` | string | `allow`, `deny` or `escalate`. Only `allow` authorises signing. |
| `payload_hash` | string | §2. |
| `policy_bundle_hash` | string | `sha256:…` of the active bundle (LLD §5.4). |
| `reservation_id` | string \| null | Limiter reservation to commit after broadcast. |
| `iat` | int | Issued at, Unix seconds. |
| `exp` | int | Expiry, Unix seconds. `0 < exp − iat ≤ 300`, with a default of 60. |
| `auth_method` | string | §3.3: `api_key`, `mtls` or `none`. |
| `key_id` | string | §3.3: the credential's ID (API key record ID; later a SPIFFE ID). `""` only when `auth_method` is `none`. |
| `agent_id` | string | §3.3: the agent the credential is issued to. `""` when the credential names none, and always `""` when `auth_method` is `none`. |

### 3.3 Requester identity

The identity claims are the **authenticated identity of the request** (`auth.Identity`: `method`, `key_id`, `agent_id`, plus its `tenant`), as established by the gateway's authenticator. They MUST NOT be taken from the request body. In particular `agent_id` is the credential's agent, not `actor.agent_id`.

- Authenticated (`api_key`, `mtls`): `key_id` MUST be non-empty, and the identity's tenant MUST equal `tenant`.
- Not authenticated (auth off, which `stopbard` allows on loopback only): `auth_method` = `none`, and `key_id` = `agent_id` = `""`.
- Scopes are authorisation for the gateway and are not bound.

An escalated request that is later approved gets a **new** `allow` token with the same `request_id` and `nonce`, a fresh `iat`/`exp`, and the identity of the caller **that requested it**, not the approver's. The approver is in the decision's `approvals` and in the audit log, not the token.

## 4. Verification

A verifier is configured with a **pinned** key set (`kid` → public key, distributed via `/v1/keys` out of band and never fetched from a token), its own `aud`, the expected `iss` and `tenant`, a clock, and a replay store. Each verification is given the exact action about to be signed and the **authenticated identity of the request it came from** (the zero identity when auth is off). In gatekeeper mode that is the identity the gateway authenticated for the request, or, for an approved escalation, the requester recorded with the escalation. It MUST run these steps in order and stop at the first failure. Every failure means **do not sign**.

| # | Check | Error code |
|---|---|---|
| 0 | Exactly three segments, each strict unpadded base64url | `MALFORMED` |
| 1 | Header is JCS-canonical, has exactly `{alg, kid, typ}`, `alg` = `EdDSA` and `typ` = `stopbar-decision-v2+jws`. A v1 token (`typ` = `stopbar-decision+jws`) fails here. | `BAD_HEADER` |
| 2 | `kid` is in the pinned key set | `UNKNOWN_KEY` |
| 3 | The signature is 64 bytes and verifies. **No claim is read before this step.** | `BAD_SIGNATURE` |
| 4 | Payload is JCS-canonical (this also rejects duplicate members) | `NON_CANONICAL` |
| 5 | Exactly the fifteen claims of §3.2, each of the right type, and the identity claims well-formed (§3.3: a known `auth_method`; `key_id` non-empty unless `none`; `key_id` and `agent_id` empty for `none`) | `BAD_CLAIMS` |
| 6 | `v` = 2 | `BAD_VERSION` |
| 7 | `iss`, `aud` and `tenant` equal the verifier's own values | `WRONG_ISSUER` / `WRONG_AUDIENCE` / `WRONG_TENANT` |
| 7d | `auth_method`, `key_id` and `agent_id` equal the authenticated identity of the request being signed (`none`, `""`, `""` when it is unauthenticated), and, when authenticated, that identity's tenant equals `tenant` | `WRONG_IDENTITY` |
| 8a | `0 < exp − iat ≤ 300` | `TTL_INVALID` |
| 8b | `iat ≤ now + 5s` (clock skew) | `NOT_YET_VALID` |
| 8c | `now < exp` (`exp` is exclusive, with no skew) | `EXPIRED` |
| 9 | `outcome` = `allow` | `NOT_ALLOWED` |
| 10 | `payload_hash` equals §2 recomputed **from the transaction or call the adapter is about to sign**, never from a value the requester supplied alongside the token | `PAYLOAD_MISMATCH` |
| 11 | `(iss, tenant, nonce)` has not been accepted before. Record it until `exp` only after steps 0–10 pass, so a failed attempt (including a wrong identity) never burns the nonce. | `REPLAYED` |

The replay store MUST be durable across adapter restarts for at least the maximum TTL (300 s).

## 5. Threats addressed

Everything in v1 §5, plus:

| Threat (HLD §8) | Defence |
|---|---|
| A token issued to one caller used to sign for another (stolen from a response, a log or a shared queue) | Step 7d: the adapter compares the token's identity with the authenticated identity of the request it is signing. |
| A spoofed `actor.agent_id` in the body carried into the signed decision | §3.3: the bound agent is the credential's. The gateway already rejects a body that disagrees (CS-103 increment 1). |
| A token minted with auth off accepted by an authenticated deployment, or the reverse | `auth_method` = `none` is explicit, and step 7d compares it like any other method. |
| An approver's identity substituted for the requester's | §3.3: an approved token binds the requester; the approver is audited separately. |
| Downgrade to a v1 token, which carries no identity | Step 1 (`typ`), then steps 5–6 if a v1 claim set is put under the v2 `typ`. |
| Changing the identity under a valid signature, or swapping `kid` to another pinned key | Step 3 runs before any claim is read. |

## 6. Versioning

Any change to the header, the claims, the canonical action or the verification order bumps `v` and the `typ`. Verifiers reject versions they don't know. The production verifier accepts v2 only.
