# Stopbar — Low-Level Design

| | |
|---|---|
| Version | 0.2 (draft) |
| Date | 2026-11-04 |
| Related | [PRD](PRD.md) · [HLD](HLD.md) · [TASKS](TASKS.md) |

---

## 1. Repository layout

```
stopbar/
├── cmd/
│   ├── stopbard/        # service / sidecar binary
│   └── stopbar/         # CLI
├── internal/
│   ├── gateway/             # HTTP API, authN, nonce/TTL
│   ├── engine/              # pipeline orchestration, fail-closed mapping (CS-104)
│   ├── model/               # ActionRequest, Decision, IntentSummary, AuditRecord
│   ├── normalize/           # raw → ActionRequest
│   ├── decode/evm/          # ABI decode, risk flags
│   ├── enrich/              # price, balance, destination registry, slippage, provenance, deploy age
│   ├── policy/              # Cedar schema, loader, evaluator, bundle hashing
│   ├── limiter/             # sliding windows, reserve/commit, circuit breaker
│   ├── escalate/            # routing, approvals, channels (cli, slack, telegram)
│   ├── decision/            # token signing (JWS, EIP-712), key providers
│   ├── signer/              # adapters: local, awskms, turnkey
│   ├── audit/               # hash chain, checkpoints, verify, rekor
│   └── store/               # bbolt, postgres, redis implementations
├── sdk/
│   ├── typescript/
│   └── python/
├── corpus/
│   ├── schema.json
│   └── attacks/*.yaml
├── examples/policies/
├── spec/                    # versioned open specs (policy schema, decision token, corpus)
├── test/replay/             # replay harness
├── research/agentdojo/      # Phase 1R eval harness (Python)
└── docs/
```

## 2. Core interfaces (Go)

As implemented in `internal/engine` (CS-104). Components are consumed through these interfaces, and each component package (CS-111, CS-121, CS-141, CS-161, CS-171) implements one.

```go
// engine.Engine implements gateway.Evaluator. Evaluate always returns a decision.
Evaluate(ctx, model.ActionRequest) (model.Decision, error)
Commit(ctx, requestID, txRef string) error   // POST /v1/actions/{id}/commit (CS-105)
Release(ctx, requestID, reason string) error // POST /v1/actions/{id}/release
Owner(requestID string) (tenant, agent string, ok bool) // who may settle it
// Escalation lifecycle (CS-151/152, §9): approve re-runs; exec (gatekeeper: sign + commit) runs on allow
// with the recorded requester identity, which the token binds (decision-token v2), not the approver.
// sig is an Ed25519-signed envelope (spec/approval-signature-v1.md); Approvers + ApprovalQuorum set M of N.
Approve(ctx, id string, sig approval.SignedEscalation) (model.Decision, error)
ApproveWith(ctx, id string, sig approval.SignedEscalation, exec Execute) (model.Decision, error)
Reject(ctx, id string, sig approval.SignedEscalation) (model.Decision, error)
Status(ctx, id string) (model.EscalationStatus, error) // GET /v1/decisions/{id}

type Decoder interface {
    Supports(a model.Action) bool
    Decode(ctx, a model.Action) (model.IntentSummary, error)
}
type Enricher interface {
    Enrich(ctx, req *model.EnrichedRequest) error // must set staleness markers; may only ADD taint
}
type Policy interface {
    Evaluate(ctx, req model.EnrichedRequest) (PolicyResult, error) // {Outcome, Reasons, BundleHash}
}
type Limiter interface { // derives its own keys/amounts from the enriched request
    // Each call carries the audit record describing it, written in the SAME
    // transaction as the state change (failure wraps ErrAuditUnavailable).
    Reserve(ctx, id string, req model.EnrichedRequest, ttl time.Duration, rec *model.AuditEntry) error // ErrCapExceeded, ErrCircuitOpen
    Commit(ctx, id, txRef string, rec *model.AuditEntry) error
    Release(ctx, id string, rec *model.AuditEntry) error // ErrUnknownReservation / ErrReservationExpired: nothing held
    Owner(id string) (tenant, agent string, ok bool)     // the reservation's requester (CS-105)
}
type PendingStore interface { // escalations; Put writes the record AND its audit record in one transaction
    Put(ctx, e PendingEscalation, rec *model.AuditEntry) error
    Get(ctx, id string) (PendingEscalation, bool, error)
}
type Signer interface { // decision.Signer: Ed25519, stdlib, compact JWS hand-rolled (no JOSE library)
    // requester is the authenticated auth.Identity (zero when auth is off),
    // never the body's actor. spec/decision-token-v2.md
    Sign(ctx, requester auth.Identity, req model.ActionRequest, d model.Decision) (token string, err error)
}
// Keys are served as decision.JWK (our own RFC 8037 OKP type, with a status
// of active or retired) at /v1/keys. There is no jose.JSONWebKey in the core.
type AuditLog interface {
    Append(ctx, typ model.AuditRecordType, body any) error
}
```

Pipeline: **normalize** (bind `payload_hash`, decision-token-v1 §2) → **decode** (first decoder that `Supports`) → **enrich** → **policy** → **sign** (allow only; changes no state) → **reserve + audit** (allow: one transaction) or **audit** (deny/escalate).

- Every component call runs with a stage timeout (default 1 s) and panic recovery. A component that ignores `ctx` is abandoned, and its partial output is never read.
- Writes that record a decision or a state change that has already happened (the decision's audit append, `Commit`, `Release`) run **detached from the request's context**. They keep its values but not its cancellation, and have their own timeout (`AuditTimeout`, default 5 s). A client that disconnects mid-request can't leave a decision unaudited, and a commit after signing is recorded even if the caller has gone.
- The engine enforces invariants between stages:
  - The decoder may not render a payload other than the bound one.
  - Enrichers may not change the action or intent, and may not remove a provenance label from `taint`.
  - The policy result must have a known outcome, reasons for deny or escalate, and a valid bundle hash.
- Only allow reserves limiter capacity and gets a token. Escalations do not reserve: approval (CS-151) re-runs the limiter, so pending escalations cannot tie up caps.
- An allow's reservation and its audit record are **one transaction**, so an allow exists only if it is recorded. If that write fails, nothing is reserved, the token never leaves, and the caller gets a deny with `FAIL_CLOSED_AUDIT`. Denials that can't be audited increment `stopbar_audit_unavailable_denials_total` and log at high severity.
- Deny reasons carry a code and a fixed public message. Component errors are logged, never returned.

## 3. Data model

### 3.1 ActionRequest

```json
{
  "id": "req_01JD…",                 // ULID, client-generated
  "tenant": "acme",
  "nonce": "b64-16-bytes",
  "issued_at": "2026-11-02T10:00:00Z",
  "ttl_seconds": 60,
  "actor": {
    "agent_id": "trading-bot-1",
    "workload_identity": "spiffe://acme/agents/trading-bot-1",
    "session_id": "sess_…",
    "on_behalf_of": "user:123"
  },
  "action": {
    "kind": "evm_tx",                  // evm_tx | tool_call | withdrawal
    "chain_id": 8453,
    "from": "0x…",
    "to": "0x…",
    "value_wei": "0",
    "data": "0xa9059cbb…",
    "tx_type": 2,                      // EIP-1559 only; the complete unsigned tx is sent and bound
    "tx_nonce": "7",
    "gas_limit": "100000",
    "max_fee_per_gas": "2000000000",
    "max_priority_fee_per_gas": "1000000000",
    "tool": null,
    "args": null
  },
  "provenance": {
    "labels": ["untrusted_onchain", "decoded"],
    "sources": [
      {"label": "untrusted_onchain", "ref": "nft:base:0x…/42", "hash": "sha256:…"}
    ],
    "sdk": {"name": "stopbar-ts", "version": "0.1.0"}
  },
  "parent_request_id": null
}
```

### 3.2 IntentSummary

```json
{
  "kind": "erc20_transfer",
  "asset": {"chain_id": 8453, "address": "0x…", "symbol": "DRB", "decimals": 18},
  "amount": "50000000000000000000000",
  "destination": "0x…",
  "flags": ["new_destination"],          // see §6.2
  "human": "Transfer 50,000 DRB (~$174,000) on Base to 0x9f3…c21 (never seen before).",
  "swap": null,                          // swaps only: {exact_in, token_in, amount_in, token_out, amount_out}
  "payload_hash": "sha256:…"
}
```

`swap` carries a swap's terms in raw units (token `""` = native) so the enricher can price both sides for `excessive_slippage` (§6.2). Exact-in: `amount_in` is exact and `amount_out` the minimum accepted. Exact-out: `amount_out` is exact and `amount_in` the most paid. Enrichers may append to `flags` (the registry and limiter flags below) but never change anything else in the intent.

### 3.3 EnrichedRequest (policy context)

| Field | Type | Source |
|---|---|---|
| `amount_usd` | decimal | price oracle; `null` + `price_stale=true` if stale. **Decided (CS-131):** `amount_usd` becomes optional in the schema (`amount_usd?`), so a stale price reaches the `stale-price` escalate policy. This is safe: a policy that reads it without `context has amount_usd` errors, and errors deny. Token-count caps still apply without a price. The rendered intent must say "price unavailable", never $0. Until CS-131 the schema requires it, so a stale price currently denies. |
| `pct_of_balance` | decimal | balance provider |
| `approval_usd?` | decimal | price oracle. It's the value a **bounded** approval lets the spender move. It's absent for unlimited approvals and for anything that isn't an approval, so a policy must test `context has approval_usd`. An approval itself counts as $0 of spend (`amount_usd`); its risk lives in this field and in the decoder's flags. The starter pack's `bounded-approval` permits ≤ $1,000 to a known spender. |
| `velocity.{1m,1h,24h}.usd` / `.count` | decimal/int | limiter snapshot |
| `destination.known` | bool | destination registry (§6.4). The sending wallet itself always counts as known. |
| `destination.similar_to_known` | bool | address-similarity check against the registry (§6.4); false when known |
| `taint` | set<string> | provenance |
| `minutes_since_code_change` | int/null | deploy events (Phase 4) |
| `intent.flags` | set<string> | decoder |

### 3.4 Decision

```json
{
  "request_id": "req_…",
  "outcome": "deny",                       // allow | deny | escalate
  "reasons": [{"code": "POLICY", "policy_id": "taint-unknown-destination", "message": "Untrusted on-chain content in context; destination not allowlisted"}],
  "policy_bundle_hash": "sha256:…",
  "payload_hash": "sha256:…",
  "approvals": [],
  "reservation_id": null,
  "issued_at": "…",
  "expires_at": "…",                        // = issued_at + 60s default
  "token": "…"                              // allow only: decision token (spec/decision-token-v2.md)
}
```

Each reason has a `code`: `POLICY` for a matched policy (with `policy_id`), otherwise an engine code from §12.

### 3.5 AuditRecord

```json
{
  "seq": 10423,
  "ts": "…",
  "type": "decision",                       // request | decision | approval | policy_change | commit | release | override
  "body": { /* canonical JSON of the event */ },
  "prev_hash": "sha256:…",
  "hash": "sha256(prev_hash || jcs(body) || seq || ts)"
}
```

Canonicalisation: RFC 8785 (JCS).

## 4. Gateway

- Transport: HTTP/1.1 + JSON v1; gRPC later.
- AuthN: mTLS (service mode) with SPIFFE IDs; API key (sidecar/dev only).
- Checks in order. Each one rejects with the typed code shown in §4.2. Body size comes first so oversized input is never parsed.
  1. method → `Content-Type: application/json` → body ≤ 64 KB
  2. auth (CS-103)
  3. well-formed JSON via RFC 8785. This also rejects invalid UTF-8, duplicate members and trailing data.
  4. no integer beyond ±2^53 (decision-token-v1 §2.2)
  5. **exact-case keys**. `encoding/json` matches keys case-insensitively, so `"To"` next to `"to"` would otherwise be a parser differential.
  6. strict decode with unknown fields rejected → `ActionRequest.Validate()`
  7. **freshness** (CS-102), two-sided. Accepted only while `issued_at − 30 s ≤ now < issued_at + ttl_seconds + 30 s`. Too far ahead is `ISSUED_IN_FUTURE`, past the end is `EXPIRED`.
  8. **nonce consumed**: an atomic check-and-set on `(tenant, agent, nonce)`, with components quoted so no tenant can burn another's nonces. This happens **before evaluation**, so a denied request can't be retried with its nonce, and neither can one answered 503. Nonces are written to bbolt (`-state-dir`) before they take effect and kept for max TTL + 2× skew, so a restart can't reopen a replay. If the store fails, the request fails closed (500).
- **No clock override, ever.** `gateway.Config.Clock` exists for unit tests only, and `stopbard` has no flag for it: a settable clock would be a switch that turns freshness off. Old fixtures stay valid because the corpus replay treats requests as templates (fresh `issued_at` and nonce per run, rewritten bytes logged).
- There is no JSON-schema library in the request path. `spec/schemas/*.json` are for non-Go clients and CI, and `internal/model` is authoritative.
- Per-requester API rate limit (token bucket) protects availability, separate from value limiter.

### 4.1 API

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/evaluate` | Evaluate an ActionRequest. Returns the Decision for every outcome: `200` allow (+ signed tx in gatekeeper mode), `202` escalate (with `escalation_id`), `403` deny. |
| GET | `/v1/decisions/{request_id}` | Poll an escalation (CS-152): `model.EscalationStatus` (`spec/schemas/escalation_status.v1.schema.json`) with `state` pending / allowed / denied / expired and the decision. Status as safe as evaluate's: `202` pending, `200` allowed (decision carries the token, and the signed tx in gatekeeper mode), `403` denied or expired. Visible to the requester (evaluate key, same tenant and agent) and its tenant's approvers; anyone else gets `404`. A pending escalation past its window is resolved as expired (audited) when polled. |
| POST | `/v1/actions/{request_id}/commit` | `{"tx_ref": "0x…"}`: report the broadcast tx → commit reservation (CS-105). `200 {"state":"committed"}`; same tx_ref again `200` (idempotent); a lapsed reservation still records the spend (`200`, `"late": true`); another tx_ref `409 CONFLICT`; released/unknown `404` |
| POST | `/v1/actions/{request_id}/release` | Optional `{"reason": "…"}`: abandon → release reservation. `200 {"state":"released"}`; again `200` (no-op, nothing audited); committed `409 CONFLICT`; lapsed `410 RESERVATION_EXPIRED`; unknown `404` |
| GET | `/v1/approvals/{escalation_id}` | What to sign (CS-151): `{escalation_id, payload_hash, tenant, max_expiry}` for a pending escalation; resolved or unknown `404` |
| POST | `/v1/approvals/{escalation_id}` | One signed approve vote (`approval.SignedEscalation`, spec/approval-signature-v1.md §2): `202` vote recorded, quorum not met; on quorum, re-evaluate against current state (§9) and answer with the decision's status. A signature that fails verification is a `403` deny `APPROVAL_SIG_<code>` (or `APPROVAL_SELF_APPROVAL`), audited, the escalation stays pending; same owner again `409 DUPLICATE_VOTE` |
| POST | `/v1/approvals/{escalation_id}/reject` | One signed reject vote: a valid one denies at once (`403 APPROVAL_REJECTED`), audited with the approver key and owner, and alerted (`stopbar_approval_rejects_total`) |
| POST | `/v1/contacts` | Request a destination-registry addition (CS-134, §6.4): body `ContactRequest` `{address, label?}` (`spec/schemas/contact_request.v1.schema.json`), same strict body checks as evaluate. `contacts`-scoped key; tenant and requester from the key. `202` with the pending `Contact` (`spec/schemas/contact.v1.schema.json`), whose `similar_to` lists every existing entry (active or pending) it looks like; `409 CONFLICT` if the address is already registered or pending |
| POST | `/v1/contacts/{id}/approve` | One signed approval vote on a pending addition (`approval.SignedContact`, spec/approval-signature-v1.md §3a), carried by any authenticated key of the tenant. `202` vote recorded, quorum not met; `200` once `-approval-quorum` distinct owners have signed, the contact now `cooling_off` until `active_from` = approval + `-contact-cooling-off`. A key bound to the requester `403 SELF_APPROVAL` (audited as `auth_reject`); any other failed check `400 INVALID_SIGNATURE`; same owner again `409 DUPLICATE_VOTE`; already approved `409 CONFLICT`; unknown or another tenant's `404` |
| DELETE | `/v1/contacts/{address}` | Remove an entry, whatever its status, **at once**: `contacts`-scoped key. `200` with the removed contact; absent `404` |
| GET | `/v1/contacts` | The key's tenant's entries with `status` (pending_approval / cooling_off / active, from the server clock) and `similar_to`: `{"contacts": [Contact]}`. `contacts` or `approve` scope |
| GET | `/v1/breakers/{tenant}` | Circuit breaker status (CS-124, §7.3) |
| POST | `/v1/breakers/{tenant}/reset` | One signed reset vote (`approval.SignedBreakerReset`, spec §3): `200` closed (quorum met), `202` recorded but still open, failed check `400 INVALID_SIGNATURE` |
| POST | `/v1/events/deploy` | Ingest deploy/change event (Phase 4) |
| GET | `/v1/audit?from=&to=` | Export audit range |
| GET | `/v1/keys` | JWKS of decision-signing keys |
| GET | `/healthz`, `/metrics` | Ops |

**Lifecycle routes need authentication** (they act on another request's state; `503 ENGINE_UNAVAILABLE` with auth off). Commit/release take the requester's own `evaluate`-scoped key: the reservation's tenant and agent must match, or the answer is `404` and the attempt is audited (`auth_reject`), because another agent releasing it would free capacity a still-valid token can spend. Approve, reject, breaker reset and contact approval are authorized by the **Ed25519 signature in the body** (CS-151), verified against the `-approvers` public keys, never by an API key scope: the key only identifies the HTTP caller for audit and rate limiting (with auth off on loopback, approvals and breaker reset need no credential; the contacts API still needs auth). Signed envelopes are strict JSON, ≤4 KB, no duplicate keys, no unknown fields. The settle body gets the evaluate checks (JSON, ≤4 KB, no duplicate or case-folded keys, no unknown fields).

Error body: `{"code": "NONCE_REPLAYED", "message": "…", "request_id": "…", "problems": ["…"]}`. `request_id` appears once it is known, and `problems` only for `INVALID_REQUEST`, listing every problem at once.

### 4.2 Gateway error codes

| Code | Status | When |
|---|---|---|
| `NOT_FOUND` / `METHOD_NOT_ALLOWED` | 404 / 405 | Unknown route, or wrong method (`Allow` header set) |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Not `application/json` |
| `BODY_TOO_LARGE` | 413 | Body > 64 KB |
| `MALFORMED_JSON` | 400 | Not a single well-formed JSON value |
| `DUPLICATE_KEY` | 400 | Same member twice in an object |
| `NUMBER_PRECISION` | 400 | Integer beyond ±2^53 (send it as a decimal string) |
| `UNKNOWN_FIELD` | 400 | Unknown member, or a known one with different case |
| `INVALID_REQUEST` | 400 | Wrong type, or fails `ActionRequest.Validate()` |
| `EXPIRED` | 400 | `now ≥ issued_at + ttl_seconds + 30 s` |
| `ISSUED_IN_FUTURE` | 400 | `issued_at > now + 30 s` |
| `NONCE_REPLAYED` | 400 | Nonce already used by this tenant and agent within retention |
| `UNAUTHENTICATED` / `FORBIDDEN_SCOPE` / `IDENTITY_MISMATCH` | 401 / 403 / 403 | CS-103 |
| `CONFLICT` | 409 | Commit with another tx_ref, or release, of a committed reservation (CS-105) |
| `ALREADY_RESOLVED` | 409 | Approve/reject of an escalation already allowed, denied or expired (CS-152) |
| `RESERVATION_EXPIRED` | 410 | Release of a reservation that already lapsed (nothing held) |
| `DUPLICATE_VOTE` | 409 | An approver owner already holds a live vote on this escalation, breaker trip or contact addition (CS-151) |
| `INVALID_SIGNATURE` | 400 | A breaker-reset or contact-approval envelope failed verification (spec/approval-signature-v1.md §8, §8a); the message names the check |
| `CONFLICT` (contacts) | 409 | Contact addition for an address already registered or pending, or approving an already-approved one (CS-134) |
| `SELF_APPROVAL` | 403 | An approver key bound to the requester of a contact addition tried to approve it (CS-134/151) |
| `ENGINE_UNAVAILABLE` | 503 | No engine configured (or, for lifecycle routes, no auth) |
| `INTERNAL` | 500 | Engine error or panic, the engine returned an invalid decision or one for a different request, or the nonce store failed |

**The status code alone is safe to act on.** A client that only checks whether the status is 200 can never read a deny as an allow:

| Outcome | Status | Body |
|---|---|---|
| allow | **200** | Decision |
| escalate | 202 | Decision |
| deny | **403** | Decision |

200 means allow and nothing else. Every other status, including 202, 403 and every error above, means *do not sign*. SDKs still read `outcome` from the body.

## 5. Policy engine

### 5.1 Cedar schema (excerpt)

```cedar
namespace Stopbar {
  entity Agent { tenant: String };
  entity Wallet { chain_id: Long, address: String };
  entity Destination { address: String };
  action "transfer", "approve", "contract_call", "tool_call", "withdraw"
    appliesTo {
      principal: Agent,
      resource: [Wallet],
      context: {
        amount_usd: decimal,
        pct_of_balance: decimal,
        price_stale: Bool,
        taint: Set<String>,
        flags: Set<String>,
        dest_known: Bool,
        dest_similar_to_known: Bool,
        vel_1h_usd: decimal,
        vel_24h_usd: decimal,
        vel_1h_count: Long,
        minutes_since_code_change?: Long
      }
    };
}
```

### 5.2 Outcome model

Cedar natively yields permit/forbid. Stopbar layers **escalate** via annotations:

- `@outcome("deny")` on `forbid` policies → deny.
- `@outcome("escalate")` on `forbid` policies → escalate (only if no deny matched).
- At least one `permit` must match, otherwise deny (default-deny).

Combination: `deny > escalate > allow`. Evaluate escalate-annotated policies as a separate Cedar policy set so "forbid" in that set means escalate.

Loader rules (`internal/policy`, CS-111). Every violation is reported with `file:line`, and the whole bundle is rejected.

- Every policy needs a unique `@id`, which becomes its PolicyID. The only annotations allowed are `@id`, `@outcome` and `@message` (the human text used in the decision reason).
- `@outcome` is allowed only on `forbid` and must be `deny` or `escalate`. An unannotated `forbid` denies.
- Every policy is validated against the bundle's single `.cedarschema` (strict mode).
- When no `permit` matches, the deny reason has code `DEFAULT_DENY` and no `policy_id`. Reasons list only the policies of the winning set, sorted by ID.

Engine rules from the Cedar spike ([ADR 0001](adr/0001-cedar.md)):

- **Any `Diagnostic.Errors` in either set → `deny` / `FAIL_CLOSED_POLICY`.** cedar-go skips policies whose condition errors, so an erroring `forbid` would otherwise not fire (fail open).
- `@id` is an annotation, not the cedar-go PolicyID (`policy0..N`). The loader maps `@id` to PolicyID and rejects missing or duplicate IDs. An unannotated `forbid` means deny, and `@outcome` on a `permit` is rejected.
- Decimals use methods (`.greaterThan(decimal("0.20"))`), not `>`. Bundles and requests are validated against the schema before activation and before evaluation.
- Cedar `decimal` is int64 with 4 fractional digits (about ±9.2e14). Only USD values reach Cedar, rounded toward the stricter outcome. Raw on-chain units stay in the limiter.

### 5.3 Example policy (`examples/policies/agent-wallet.cedar`)

```cedar
@id("base-permit")
permit (principal, action in [Stopbar::Action::"transfer", Stopbar::Action::"contract_call"], resource);

@id("taint-unknown-destination") @outcome("deny")
forbid (principal, action, resource)
when { context.taint.containsAny(["untrusted_web","untrusted_onchain","untrusted_email"]) && !context.dest_known };

@id("unlimited-approval") @outcome("deny")
forbid (principal, action == Stopbar::Action::"approve", resource)
when { context.flags.contains("unlimited_approval") };

@id("delegatecall") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("delegatecall") };

@id("large-share-of-balance") @outcome("escalate")
forbid (principal, action, resource) when { context.pct_of_balance.greaterThan(decimal("0.20")) };

@id("address-poisoning") @outcome("escalate")
forbid (principal, action, resource) when { context.dest_similar_to_known && !context.dest_known };

@id("stale-price") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };
```

### 5.4 Bundles

- A bundle = policies + schema + limiter config + allowlists. Its hash is `sha256(JCS({"v":1,"files":[{"name","sha256"}…]}))`, with files sorted by name and hashed over their exact source bytes (ADR 0001 condition 3). Stdlib only, and independent of file order and of cedar-go's re-serialisation.
- Activation requires: valid schema, replay suite passes, M-of-N signed approval (configurable; default 1-of-1 in dev).
- **Cooling-off:** changes that *loosen* caps take effect after a configurable delay (default 24h) — defeats "raise the cap, then attack".

## 6. Decoder (EVM)

### 6.1 Pipeline

Implemented in `internal/decode/evm` (CS-141/142). It is stdlib-only, like the trusted core, because it decides what the policy sees. Its selector table is cross-checked against keccak-256 in `internal/signer`, where go-ethereum is allowed.

1. **Native transfer** if `data` is empty.
2. **Selector lookup** in the built-in table:
   - ERC-20: transfer, transferFrom, approve, increaseAllowance, EIP-2612 permit
   - ERC-721 and ERC-1155 transfers, setApprovalForAll
   - Permit2: approve, permit single and batch, transferFrom
   - Uniswap V2 router, V3 SwapRouter and SwapRouter02 swaps
   - Universal Router `execute`: V2/V3 swaps, Permit2 permit and transfer, sweep, pay-portion, wrap and unwrap. Other commands are `opaque`.
   - WETH `deposit()`/`withdraw()`, but only to the chain's canonical wrapped-native address (`evm.WrappedNative`); the same selectors elsewhere stay `unknown_call`
   - Safe `execTransaction`, MultiSend, and owner/module/guard changes
   - Proxy upgrades
   - Multicall: Uniswap `multicall` variants, Multicall3 `aggregate*`

   A local 4byte fallback, and 1inch/0x routers, aren't implemented yet. Those calls are `unknown_call`.
3. **Recursion** into multicall, Safe and MultiSend inner calls, and Universal Router commands, up to depth 4. Anything deeper is `opaque`.
   - `IntentSummary.calls` holds the inner intents.
   - **The top-level `flags` are the union over every depth**, so a flag can't hide inside a batch, and policies match flags whatever the top-level action is.
   - If exactly one inner call moves value, its asset, amount and destination are lifted to the top. With several, the top has none and is flagged `multi_transfer` (enrichment fails closed until CS-131 prices each outflow).
   - Native value attached to a call that doesn't account for it is shown as its own outflow.
4. **Errors and unknowns:**
   - A malformed call to a known selector is a decode error (`FAIL_CLOSED_DECODER`), never a guess.
   - An unknown selector is flagged `unknown_call` (the policy decides; the default is escalate).
5. **Fee terms** are checked against per-chain limits (`evm.Chains`: max fee per gas, gas limit, total max fee). A transaction for an unlisted chain is a decode error, since fee sanity can't be judged without the chain.

### 6.2 Risk flags

| Flag | Rule |
|---|---|
| `unlimited_approval` | ERC-20 approve/increaseAllowance/permit amount ≥ 2^255; Permit2 amount ≥ 2^159; `setApprovalForAll(_, true)`. ("≥ 10× balance" needs the balance, so it belongs to the enricher.) |
| `delegatecall` | Safe `operation = 1` to anything other than a canonical MultiSend carrying `multiSend`; any MultiSend entry with `operation = 1` |
| `proxy_upgrade` | `upgradeTo`, `upgradeToAndCall`, Safe `changeMasterCopy`, `setFallbackHandler` |
| `wallet_admin` | Safe owner, threshold, module or guard change |
| `third_party_from` | `transferFrom`-style move whose source isn't the sender (e.g. spending someone's allowance) |
| `multi_transfer` | more than one outflow in one transaction |
| `new_destination` / `similar_destination` | added by the destination registry enricher (§6.4, CS-133), not the decoder: destination not registered (and not the sender) / not registered but similar to a registered address |
| `first_time_contract` | needs a per-tenant record of contracts called (CS-142) |
| `opaque` | nesting > depth, or a Universal Router command that isn't decoded |
| `min_out_zero` | exact-in swap with minimum output 0 (Uniswap V2/V3 routers, SwapRouter02, Universal Router) |
| `excessive_slippage` | added by the price enricher (CS-145): for any swap at any depth (`IntentSummary.swap`), the out side is worth less than (1 − tenant max slippage, default 3%) of the in side at oracle prices. Exact-in compares the minimum output with the input; exact-out the output with the maximum input. Wrapped native is priced as native. A swap whose tokens can't both be priced sets `price_stale`, so the starter pack escalates instead of trusting an unchecked limit. |
| `soft_cap_exceeded` | added by the limiter: the request would cross a soft (`escalate`) cap (§7.3a) |
| `excessive_fee` | fee terms above the chain's limits (`evm.Chains`) |
| `unknown_call` | selector unknown |

### 6.3 Human rendering

Template per `kind`, amounts formatted with decimals and USD, addresses shortened `0x9f3…c21` **plus** a 6-word checksum phrase derived from the full address (defeats visual look-alike). The rendered text and `payload_hash` are sent together; approvals sign over `payload_hash`.

### 6.4 Destination registry (CS-133/134, FR-IR-2)

Implemented in `internal/enrich` (`Registry`). It is an engine `Enricher`, wired after the price/balance enricher and before the limiter (whose unknown-destination caps read `destination.known`), in both the chain and the devstub configuration.

- **Storage:** bucket `destinations_v2` in the shared state file, keyed by quoted tenant + lowercase address, value `model.Contact` `{id, tenant, address, label?, requested_by, requested_by_agent?, requested_at, votes?, quorum?, approved_by?, approved_at?, active_from?, similar_to}`. `status` is derived when read: quorum not met → `pending_approval`; approved and `now < active_from` → `cooling_off`; otherwise `active`. CS-133's `destinations_v1` entries are not read (they become unknown, which only tightens policy). It is read on every evaluation, so a change applies to the next request.
- **Lifecycle (CS-134, ADR 0004; signed approvals ADR 0005).** Adding a destination loosens policy, removing one tightens it, so they are treated differently:
  - **Request** (`POST /v1/contacts`, `contacts` scope): recorded as pending. The address is checked against **every** entry of the tenant, active and pending, with the same similarity rule as the enricher, and every match (address + label) is stored in `similar_to`, in the audit record, in `GET /v1/contacts` and in the CLI output, so the approver sees a poisoning attempt before approving. An exact duplicate (case-insensitive) is refused `409`.
  - **Approve** (`POST /v1/contacts/{id}/approve`, CS-151, ADR 0005): each approver signs `{tenant, contact_id, address, decision: "approve", expiry}` locally with their Ed25519 approver key (spec/approval-signature-v1.md §3a); the registry verifies it against `-approvers` and the stored entry and records the vote. A key whose owner matches the requester's API key id or agent id is refused (`SELF_APPROVAL`). When `-approval-quorum` distinct owners hold live votes (a vote counts until its signature's expiry, at most 1h), the entry is approved (`approved_by` = the approver ids) and it sets `active_from = approval + cooling-off` (`-contact-cooling-off` / config `contact_cooling_off`, default **24h**; 0 is allowed with a warning; negative refused). The cooling-off runs from the approval, so a late approval cannot activate at once, and the rest of the team gets the whole window to see and remove it.
  - **Remove** (`DELETE /v1/contacts/{address}`, `contacts` scope): applies at once, whatever the status.
  - With auth off or no registry the API answers `503`; stopbard warns at start if `-dev-world` runs without `-auth-keys`.
- **Audit:** `contact_request` (`{contact, identity}`), `contact_approval` (one per accepted vote: `{event: vote|approved, contact, identity, approver, kid, owner, cooling_off?}`) and `contact_removal` (`{contact, identity}`), each **in the same transaction** as the change. Refused changes (duplicate, unknown id, failed signature, duplicate vote, self-approval) change nothing; a self-approval or missing scope is recorded as `auth_reject`.
- **Facts:** judged against entries **active at the server clock** (no clock override in stopbard; injected clocks in unit tests only). A pending or cooling-off addition is still a new destination: `known` and the unknown-destination soft caps are unchanged until `active_from`. `known` = the destination is active for the request's tenant, or is the sending wallet. `similar_to_known` = not known, and it shares at least 4 leading **and** 4 trailing hex digits with an active address, or at least 8 at either end (what wallets and explorers show; a random address matches by chance with probability ~3 × 16⁻⁸). A request with no destination is neither, and tool calls are skipped. The starter pack escalates `address-poisoning` (`dest_similar_to_known && !dest_known`).
- **CLI:** `stopbar contacts add <address> [--label L] | approve <id> --approver-key FILE | remove <address> | list`, each with `--url URL --key KEY` (`approve` reads the entry from the listing and signs it locally), talks to a running stopbard; no restart is needed. The offline state-file path (CS-133) is removed: the approval, separation and cooling-off above are what make an API path safe against a compromised requester (T3), and an offline path would bypass them. With `-dev-world`, the world's `known_destinations` seed the registry for `-tenant` as already active (`requested_by`/`approved_by: dev-world`, audited as `contact_request`): the operator's world file is the approval.

## 7. Limiter

### 7.1 Keys and windows

Key = `(tenant, scope, id, window)` where scope ∈ {`agent`, `wallet`, `wallet+asset`, `destination`, `tenant`}. `destination` scope carries a `max_count` by default (5 per 24h for destinations not in the registry, as a soft cap that escalates; CS-145) so salami draining below per-tx caps is bounded. Windows: 1m, 1h, 24h (configurable).

**Per-transaction caps** (CS-123, FR-LIM-1) use window `tx`: they judge one request on its own and accumulate nothing. They take `max_usd` (value + max fee, like every USD cap), `max_units` (wallet+asset) and `max_pct_of_balance` (`tx` only; a decimal fraction of the wallet's balance of the moved asset). A `tx` rule can't take `max_count`. An unknown balance on a request that moves value is `ErrNoBalance` and fails closed (`FAIL_CLOSED_LIMITER`), like `ErrUnpriced`.

Size is capped twice, on purpose:

- **Soft, in policy context.** `amount_usd` and `pct_of_balance` (§3.3) let a policy escalate, as the starter pack's `large-share-of-balance` does above 20%. That's how the OpenClaw fixture (CS-2026-0002) escalates.
- **Hard, in limiter config.** A `tx` rule denies with `CAP_EXCEEDED`. Escalations reserve nothing, so a hard cap doesn't change an escalation, but approval (CS-151) re-runs the limiter. A human can waive an escalation, never a cap. Hard caps hold at T3/T4. Policy thresholds hold only as far as the policy author's numbers.

### 7.2 Algorithm — sliding window with sub-buckets

Each window is stored as 60 sub-buckets (e.g. 1h → 60 × 1m). Current usage = sum of committed + reserved in live sub-buckets.

```
Reserve(id, keys, amt, ttl):
  atomically (Redis Lua script / Postgres SERIALIZABLE / bbolt tx):
    for k in keys:
      used = committed(k) + reserved(k)
      if used + amt > cap(k): return ErrCapExceeded{k}
    for k in keys:
      reserved(k) += amt in current sub-bucket
    store reservation{id, keys, amt, expires=now+ttl}
Commit(id):   move reservation amt from reserved → committed
Release(id):  remove reservation amt
Janitor:      every 5s release expired reservations (expired = not committed within ttl)
```

Amount is two-dimensional `{usd, count}`; caps can be set on either. Token-count caps are applied in addition to USD caps so oracle manipulation can't bypass.

### 7.3 Circuit breaker

`tenant` scope with a hard outflow cap per 1h. On breach: all subsequent `evaluate` → deny `CIRCUIT_OPEN` until M-of-N reset. Emits high-severity alert.

Implemented in CS-124 (`internal/limiter/breaker.go`):

- **Config:** a tenant-scope rule with `circuit_breaker: true` (window 1m, 1h or 24h, never `tx`). Breaker rules are checked before every other cap.
- **Trip:** a `Reserve` that would push the tenant over that rule trips the breaker and returns `ErrCircuitOpen`, so the request is denied `CIRCUIT_OPEN`.
  - The trip is written to bbolt (`limiter_breakers_v1`) in the same transaction as an audit record of type `breaker` (`event: trip`).
  - The trip logs at high severity and increments `stopbar_circuit_breaker_trips_total` on `/metrics`. Alert on any increase.
  - If the trip can't be written, the breaker still opens in memory (failing closed) and the request denies `FAIL_CLOSED_AUDIT`.
- **While open:** the engine asks `Breaker.CircuitOpen(tenant)` right after normalize, before decode or policy. Every request for the tenant is denied `CIRCUIT_OPEN`, including ones policy would only escalate and approvals of earlier escalations, and `Reserve` refuses too. Other tenants are unaffected. An open breaker survives restart and the window rolling over: only a reset closes it.
- **Reset (M of N):**
  - `POST /v1/breakers/{tenant}/reset` takes one Ed25519-signed reset envelope `{tenant, trip_request_id, decision: "reset", expiry}` (CS-151, spec/approval-signature-v1.md §3), signed locally by `stopbar breaker reset --approver-key FILE`. A failed check is `400 INVALID_SIGNATURE` and writes nothing.
  - Each vote is durable and audited (`event: reset_vote`, with approver id, kid and owner) before it counts, and is bound to the current trip.
  - An owner that already holds a live vote (any of its keys) is refused with `409 DUPLICATE_VOTE`, and nothing is written.
  - **A vote expires at its signature's expiry** (at most 1 hour after it is checked; each vote carries `expires_at`). An expired vote no longer counts. `GET` lists it under `expired_votes`, separate from the live `votes`. The next vote discards it and writes an `event: vote_expired` record in the same bbolt transaction as that vote, so a quorum has to be assembled within one hour. `GET` writes nothing.
  - When `-breaker-quorum` distinct owners hold live votes, the breaker closes (`event: reset`, `stopbar_circuit_breaker_resets_total`). The quorum defaults to 2. stopbard and the limiter both refuse anything below 2 (`model.MinBreakerQuorum`).
  - The endpoint answers 200 when the vote closed the breaker, 202 when it was recorded below quorum (still open), 404 when the breaker isn't open and 409 for a repeat vote. Reset needs auth even on loopback. `GET /v1/breakers/{tenant}` returns `model.BreakerStatus` (`spec/schemas/breaker_status.v1.schema.json`).
- **CLI:** `stopbar breaker status --tenant T` and `stopbar breaker reset --tenant T --key K [--key K2 …]`. The reset fails ("reset refused: n of M") while the quorum isn't met.
- **Tests:**
  - Corpus CS-2026-0014 trips the breaker over HTTP. The replay checks that every later step keeps denying and that `/metrics` reports the trip.
  - `scripts/e2e_breaker.py` runs against the live binaries. It checks the quorum-1 refusal, the 1-of-2 refusal, the repeat-vote 409, the 1-hour `expires_at` in `GET` and the 2-of-2 reset.
  - Expiry itself (vote, more than 1 hour, second vote → still open; two fresh distinct votes → closed; the discard audited with the vote) is unit-tested with an injected clock. stopbard has no clock override, so the e2e can't wait the hour.

**Demo configs** (`research/walletagent/demo.py`, `demo_live.py`, `demo_testnet.py`) each carry a hard per-tx cap (`window: tx`), sized so each journey keeps its outcomes:

| Demo | Per-tx cap | Why the journey is unchanged |
|---|---|---|
| `make demo` | `max_usd: 5000`, `max_pct_of_balance: 0.25` | The 0.01 ETH payments fit. The 5 ETH transfer escalates in policy before the limiter runs. The 24h count cap still denies the second payment. |
| `make demo-live` | `max_usd: 20000`, `max_pct_of_balance: 0.25` | The approved 5 ETH is a tiny share of the 10,000 ETH fork balance and fits under the same $20k as the 1h cap. |
| `make demo-testnet` | `max_usd: 50000`, `max_pct_of_balance: 0.75` | The approved transfer is 60% of the real balance. |

### 7.3a Implementation (`internal/limiter`, CS-121/122)

- **One process, one mutex.** `Reserve`, `Commit` and `Release` are serialised. All caps are checked on all five scope keys before anything changes, so a reserve is all-or-nothing.
- **Numbers:**
  - USD is integer micro-dollars (`big.Int`). Amounts round **up** from decimal strings, and caps must be exact (at most 6 decimal places).
  - Token amounts are raw units (`big.Int`). `max_units` (wallet+asset scope) bounds loss even with no price.
  - A USD cap that applies to a request with no price is a typed `ErrUnpriced`, which fails closed.
- **Durability:** each change is written to the store (bbolt, `-limiter-db`) **before** it is applied in memory. On restart, state is rebuilt from the records, so restarting does not reset caps. Expiry is derived from the clock and needs no write. bbolt's file lock prevents two processes from sharing one state file. Multi-instance deployments need the Redis store (CS-306).
- **Windows:** 60 sub-buckets each, counted conservatively. A spend stays counted for up to one sub-bucket (window/60) longer than the window, never shorter.
- **Lifecycle:**
  - Reserving the same request ID while it is live is a no-op, and re-using a finished ID is `ErrDuplicateReservation`.
  - Commit or release of an unknown ID returns `ErrUnknownReservation`, and of a lapsed one `ErrReservationExpired`. Committing again with the same tx_ref is a no-op; with another, or releasing a committed one, is `ErrAlreadyCommitted`. Releasing a released one is a no-op (nothing written). These errors live in `model` so the gateway maps them (CS-105).
  - Each record stores its `tenant` and `agent` (`Owner(id)`), so only the requester can settle it over HTTP. Records from before this field have no owner and cannot be settled over HTTP (fail closed).
  - **A late commit still records the spend**, so loss bounding counts what actually happened.
  - The engine treats unknown or expired IDs on its own best-effort release as "nothing held".
- **Keys** quote each component, so requester-chosen tenant or agent IDs can't collide. Agent and tenant scopes are only as strong as authentication (CS-103), while wallet scopes are bound to the signing address.
- **Velocity:** the limiter is also an `Enricher`. It supplies `velocity.{1m,1h,24h}` (committed + reserved, wallet scope) to policy.
- **Soft caps (`escalate: true`, CS-145):** a rule that escalates instead of denying. The limiter's `Enrich` adds `soft_cap_exceeded` to the intent's flags when the request would exceed one (an unpriced request under a USD soft cap counts as exceeding it), and the starter pack escalates on it (`soft-cap-exceeded`). Approval re-runs enrichment and policy, so an approved request reaches `Reserve` flagged and is let past its soft caps; hard caps still apply. `Reserve` denies an **unflagged** request that would exceed a soft cap (one that raced past `Enrich`), so a soft cap is never crossed without a policy decision that saw the flag. The flag is only a fact: a bundle with no policy on it lets flagged requests through, so its soft caps are advisory (the starter pack escalates). The dev default is the salami cap `{scope: destination, window: 24h, max_count: 5, unknown_destinations_only: true, escalate: true}` (FR-LIM-2a).
- **Destination rules** skip a request with no destination (nothing to count per destination), and `unknown_destinations_only` rules skip destinations the registry knows (§6.4).
- **Sweeping costs O(lapsed):** an expiry heap plus a creation-ordered queue for retention (24h + one sub-bucket + max TTL).

### 7.4 Properties to test

- No interleaving of concurrent `Reserve` exceeds any cap. Property test: 1,000 goroutines × 20 operations. The invariant is checked under the lock after **every** state change and by 8 concurrent observers, and final usage is reconciled exactly against an independent ledger. A mutation check confirms the test fails if the cap check ignores the request's own amount.
- Expired reservations always released.
- Window rollover never double-counts or drops.

## 8. Provenance and taint

### 8.1 Labels

`trusted_user`, `trusted_system`, `tool_output`, `untrusted_web`, `untrusted_onchain`, `untrusted_email`, `untrusted_file`, `decoded`, `sensitive_internal` (Phase 3).

### 8.2 v1 — context-level taint (SDK)

```ts
const cs = new Stopbar({ endpoint, agentId });
const ctx = cs.context();                     // per agent session
ctx.add(userMessage, "trusted_user");
ctx.add(await fetchTweet(url), "untrusted_web", { ref: url });
// …model runs…
const decision = await cs.evaluate(proposedTx, { context: ctx });   // attaches ctx.labels()
```

Rules:
- `ctx.labels()` = union of labels of everything added this session (monotonic; can only reset by starting a new session).
- `decoded` is added automatically if the SDK detects encoded content (base64, hex, Morse, ROT-n, zero-width chars) in untrusted inputs (CS-183: any label not `trusted_*`). To keep false positives low on addresses, hashes and calldata, base64/hex count only when they decode to readable text, Morse needs a run of ≥ 5 valid codes, and ROT-n needs a segment that is English only under rotation. Both SDKs run the same detector against the shared fixtures in `sdk/testdata/encodings.json`.
- Labels only restrict. Missing provenance (`labels` empty) is treated as `unknown_provenance` → policy may escalate.

### 8.3 Phase 3 — field-level taint (code mode)

- Bindings exposed to the sandbox are wrappers. Each returned value is wrapped in a `Tainted<T>` carrying labels; derived values propagate labels (JS Proxy / Python wrapper objects).
- Each binding call becomes an `ActionRequest` with `action.kind = tool_call`, `tool`, `args`, and per-arg labels.
- Policy example: `forbid when action == "email.send" && context.arg_taint.body.contains("sensitive_internal") && context.recipient_external`.
- Loop accounting: each call counted in limiter scope `agent+tool`.

### 8.4 Phase 4 — infrastructure provenance

- Deploy events (`/v1/events/deploy`) from CI/CD or Kubernetes audit: `{workload_identity, artifact_digest, ts, approved_by}`.
- `minutes_since_code_change` computed per requesting workload identity.
- Unapproved artifact digest (not signed by release pipeline) → deny.

## 9. Escalation

1. Engine creates a `PendingEscalation{request, reasons, requester, issued_at, votes}`; the quorum is `-approval-quorum` distinct approver owners (at least 2 outside `-dev-world`).
2. Channel adapters push the rendered intent. Phase 1: CLI (`stopbar approve <id> --approver-key FILE`, which reads `GET /v1/approvals/{id}` and signs locally; the SDKs do the same); Phase 2: Slack/Telegram with deep link to a signing page; Phase 4: WebAuthn passkeys.
3. Approval payload = `{escalation_id, payload_hash, decision: approve|reject, expiry}`, signed with Ed25519 over `domain || JCS(object)` (spec/approval-signature-v1.md, ADR 0005). The engine verifies, in order: key configured, key's tenant, signature, decision, escalation id, payload hash recomputed from the stored action, `now < expiry ≤ now + 1h`, and (approve only) that the key's owner is not the requester. Two keys of one owner count once (`approval.Tally`).
4. Any `reject` → deny. Timeout (default 15m, `stopbard -pending-ttl`) → deny.
   **As implemented (CS-151/152):** an escalation is a `PendingEscalation` record (state pending → allowed | denied | expired) written in the same transaction as its audit record: the escalate decision on create; a `decision` deny `APPROVAL_REJECTED` with the approver identity on reject (with the vetoing kid and owner, alerted); a `decision` deny `APPROVAL_EXPIRED` on timeout (applied when the record is next touched: poll, approve or reject); an `approval` record (`event: vote`) for each accepted vote below quorum; an `approval` record with the final decision when the quorum's re-run allows (in gatekeeper mode after signing and committing, or `denied` if the adapter refuses). Records are kept after resolution so `GET /v1/decisions/{id}` reports the outcome; approve/reject of a resolved one is `409 ALREADY_RESOLVED`. An approver key bound to the requester may not approve (`APPROVAL_SELF_APPROVAL`, audited, stays pending) but may reject (spec §7). A signature failing any other check is a deny `APPROVAL_SIG_<code>`, audited, and the escalation stays pending; approver keys verify only for their own tenant. Transitions are serialised, so two approvers cannot both resolve one escalation. If the resolution of an approved allow cannot be recorded, the approval fails closed (`FAIL_CLOSED_AUDIT`, the signed bytes never leave). If the quorum's re-run does not allow, the votes are not spent: approvers resubmit.
5. **Approval re-evaluates against current state.** It does not replay the old decision. When quorum is reached, the engine re-runs **enrich → policy → limiter → sign** for the same request and `payload_hash`, with the verified approvals as a policy input (`context.approvals`: count and approver IDs). An escalation can wait up to 15 minutes, and in that time prices move, velocity windows fill and the circuit breaker can trip. A human approves the world as it was, but the system signs into the world as it is. The re-run can therefore still deny (for example `CAP_EXCEEDED`, or a deny policy that now matches) or escalate again. Policies decide what an approval satisfies: an escalate policy is written as `forbid … when { … && context.approvals.count < 1 }`, while deny policies ignore approvals. The resulting decision gets a fresh `iat`/`exp` and is audited as its own record, linked to the escalation.

## 10. Decision tokens and countersignatures

### 10.1 JWS (gatekeeper / generic)

Normative spec: [`spec/decision-token-v2.md`](../spec/decision-token-v2.md), with vectors in `spec/vectors/decision-token-v2.json` (CS-103 increment 2, [ADR 0003](adr/0003-decision-token-v2-identity.md)). v1 ([`spec/decision-token-v1.md`](../spec/decision-token-v1.md)) is frozen: Stopbar no longer issues or accepts it, and a test checks that no v1 vector verifies.

- Algorithm: EdDSA (Ed25519). The header is exactly `{alg, kid, typ}` with `typ` = `stopbar-decision-v2+jws`, and `kid` is the RFC 7638 thumbprint of a key pinned from `/v1/keys`.
- Claims (closed set, JCS-canonical): `v` (= 2), `iss`, `aud`, `tenant`, `request_id`, `nonce`, `outcome`, `payload_hash`, `policy_bundle_hash`, `reservation_id`, `iat`, `exp`, and the requester identity `auth_method`, `key_id`, `agent_id`.
- The identity claims are the **authenticated** `auth.Identity` (method, key ID, the credential's agent), never the body's `actor`. With auth off (loopback dev only) they are `none`, `""`, `""`. The engine passes the identity to `Signer.Sign` explicitly: from the gateway's context on evaluate, and from the pending record's `Requester` on approval, so an approved token binds the requester and never the approver. The signer refuses a malformed identity or one whose tenant is not the request's.
- `payload_hash` = sha256 over JCS of the normalised action (spec §2, unchanged from v1), not a chain tx hash. Every tx field, including nonce, gas and fees, is bound.
- Signer adapters **must** run the spec §4 checks in order, given the action about to be signed and the authenticated identity of its request (`Verifier.Verify(token, action, identity)`). The checks include the identity (step 7d, `WRONG_IDENTITY`), recomputing `payload_hash` from the tx they are about to sign, and single use per `(iss, tenant, nonce)`.

### 10.1a Gatekeeper adapter (`internal/signer`, CS-162; edge)

The adapter is edge code: it uses go-ethereum for secp256k1 and EIP-1559, which the stdlib lacks. It touches no key until the core verifier (`internal/decision`, stdlib only) has accepted the token. `SignTx` runs these steps in order:

1. Verify the token (decision-token-v2 §4) against the authenticated identity of the request (`SignTx(ctx, token, action, requester)`). This refuses a v1 token and a token bound to any other identity (`WRONG_IDENTITY`), recomputes `payload_hash` from the exact unsigned tx, and spends the token in the adapter's **own** spent store (`-state-dir/adapter-spent.db`, retention max TTL + 2× skew).
2. Find the key for `from`. If `Options.CodeAt` is set, read `from`'s on-chain code and refuse (`DELEGATED_WALLET`, fail closed on a read error) when it carries EIP-7702 delegation code (`0xef0100 || addr`, `signer.DelegatedTo`) to an address not in `ExpectedDelegates` — a delegated hot wallet can be driven to act as another contract (CS-146; `CodeAt` is wired once `stopbard` has a chain RPC). Type-4 (EIP-7702 SetCode) requests never reach here: the wire schema pins `tx_type` to `2`.
3. Build the transaction from the approved fields only.
4. Sign, recover the sender, and require it to equal `from`.
5. Read the *signed* tx back and require its payload hash to equal the token's.

**Gatekeeper flow:** allow → sign → `Commit(reservation, tx hash)`. `Gatekeeper.Evaluate` passes the adapter the identity the gateway authenticated; `Gatekeeper.Approve` passes the requester that `Engine.Approve` returns from the pending record (pending records keep the full `auth.Identity`, in bucket `pending_escalations_v2`). If the adapter refuses, or the commit can't be recorded, the reservation is released with the reason audited, the signed bytes are discarded, and the caller gets a 403 with `FAIL_CLOSED_ADAPTER`. `stopbar decode-tx` decodes any signed tx independently: recovered sender, every field, and its payload hash.

### 10.2 EIP-712 (co-signer, Phase 4)

```
Countersignature(address safe, bytes32 txHash, uint256 nonce, uint64 expiry, bytes32 policyBundle)
domain: {name: "Stopbar", version: "1", chainId, verifyingContract: guard}
```

`StopbarGuard` (Safe Guard) `checkTransaction` requires a valid secp256k1 signature from the configured Stopbar address over the struct. Guard keeps `usedNonces`.

### 10.3 Key providers

`local` (file, dev only), `awskms`, `pkcs11` (HSM, Phase 4), `nitro` (enclave, Phase 4).

- The `local` provider loads only with `-dev-world`, and refuses key files more open than 0600.
- Decision keys (Ed25519) and wallet keys (secp256k1) live in **separately tagged files**, so neither can be loaded as the other, and the same path for both is refused.
- **Rotation:** `KeyRing.Rotate` makes a new key active. The old key moves to retired, where it still verifies and never signs again. `/v1/keys` lists both with their status.

## 11. Audit log

Implemented in `internal/audit` (CS-171/172), per `spec/audit-hash-v1.md`.

- **One state file** (`internal/store`, bbolt, `-state-dir/state.db`) holds the limiter, nonce, spent-token and audit buckets. Each audit record is written **in the same transaction as the state change it describes**, so both are durable or neither is:

  | Record | Written with |
  |---|---|
  | `request` | the consumed nonce (gateway) |
  | `decision` (allow) | its reservation |
  | `commit` / `release` | the limiter commit or release (with the settler's identity) |
  | `contact_request` / `contact_approval` / `contact_removal` | the registry change (§6.4; CS-133 logs carry `destination_change`) |
  | `decision` (escalate) | the pending escalation record |
  | `decision` (reject / expiry), `approval` (approved) | the escalation's state change |
  | `decision` (deny) | nothing, so its own transaction |

- **Append-only.** Records are keyed by big-endian `seq`, and `hash = sha256(JCS({v, seq, ts, type, body, prev_hash}))` via `canon.RecordHash`. No code path updates or deletes a record.
- **Checkpoints.** Every N records (`-audit-checkpoint-every`, default 1000) and at shutdown, the head `{v, seq, hash, ts}` is signed with the decision key. The signature is over `"stopbar-audit-checkpoint-v1\n" + JCS`, which can never be a token's signing input. (The original sketch used a Merkle root over the range. The chain already commits to every earlier record, so signing the head is enough; Merkle inclusion proofs can be added later without changing records.)
- **`stopbar audit verify --state-dir DIR --keys keys.json [--from --to] [--require-covered]`** works offline, from the file plus saved `/v1/keys` output (each `kid` is recomputed from its key). It recomputes every hash and link and checks every checkpoint against the chain. It detects an edited byte, a deleted record (a gap in `seq`), reordered records (the key and the record's `seq` disagree, and the chain breaks), a re-hashed forgery (the next link breaks) and tail truncation (a checkpoint covers a missing record, or uncovered records with `--require-covered`). `stopbar audit export` prints records as JSON lines.
- **Unaudited denials are never silent:** `stopbar_audit_unavailable_denials_total` on `/metrics`, plus a high-severity log entry.
- Still to come: optional Rekor upload and Merkle inclusion proofs.

## 12. Error handling (fail closed)

| Code | When | Outcome |
|---|---|---|
| `FAIL_CLOSED_NORMALIZE` | Action has no payload binding (withdrawal, contract creation) or cannot be canonicalised | deny |
| `FAIL_CLOSED_DECODER` | No decoder supports the action, decoder error/panic/timeout, or decoder rendered a different payload | deny |
| `FAIL_CLOSED_ENRICH` | Enricher error/panic/timeout, or it removed taint or modified the action | deny (price staleness is not an error: the enricher sets `price_stale` and policy escalates) |
| `FAIL_CLOSED_LIMITER` | Store unavailable | deny |
| `FAIL_CLOSED_POLICY` | No active bundle, eval error, or malformed result | deny |
| `FAIL_CLOSED_SIGNER` | Signer error, panic, timeout or empty token | deny |
| `FAIL_CLOSED_AUDIT` | Audit append fails | deny (no unaudited decisions) |
| `FAIL_CLOSED_ENGINE` | Panic outside any component | deny |
| `CAP_EXCEEDED` | Reserve failed | deny |
| `CIRCUIT_OPEN` | Breaker tripped: the tripping request, then every request for the tenant until an M-of-N reset (§7.3) | deny |
| `APPROVAL_REJECTED` | An approver rejected the escalation | deny |
| `APPROVAL_EXPIRED` | The pending window passed before approval | deny |
| `APPROVAL_SELF_APPROVAL` | An approver key bound to the requester tried to approve its escalation | deny (stays pending) |
| `APPROVAL_SIG_<code>` | A signed approval failed a check (`UNKNOWN_KEY`, `WRONG_TENANT`, `MALFORMED`, `BAD_SIGNATURE`, `BAD_DECISION`, `WRONG_ESCALATION_ID`, `PAYLOAD_MISMATCH`, `EXPIRED`, `EXPIRY_TOO_FAR_AHEAD`; spec/approval-signature-v1.md §6) | deny (stays pending) |
| `NONCE_REPLAYED` / `EXPIRED` | Gateway | 400 |

Panics recovered at the engine boundary → `deny`.

## 13. Latency budget (allow path, sidecar)

| Stage | Budget |
|---|---|
| Gateway + schema | 1 ms |
| Normalise + decode | 2 ms |
| Enrich (cached price/balance) | 5 ms |
| Policy eval | 2 ms |
| Limiter reserve | 3 ms |
| Decision sign (Ed25519 local / KMS) | 1 ms / 10 ms |
| Audit append | 3 ms |
| **Total** | **~17 ms local, ~26 ms KMS** |

Price/balance cached with TTLs (prices 15s, balances 10s); cache miss beyond budget → stale → escalate per policy.

## 14. STRIDE

| Threat | Asset | Mitigation |
|---|---|---|
| Spoofing requester | Gateway | mTLS + SPIFFE; API keys dev only |
| Spoofing approver | Escalation | Approver keys / passkeys; approvals bound to payload_hash |
| Tampering with request in flight | Request | mTLS; payload_hash bound into decision |
| Tampering with policy | Bundle | M-of-N signed activation; cooling-off for loosening; audit |
| Tampering with audit | Log | Hash chain, signed checkpoints, Rekor anchor, INSERT-only role |
| Repudiation | All | Audit record per event with actor identity |
| Information disclosure | Requests, intent | Minimal logging of payload `data` beyond hash in shared channels; tenant isolation |
| DoS | Engine | Per-requester rate limits; fail closed; HA Phase 4 |
| Elevation via token reuse | Decision token | Nonce, short exp, payload binding, single-use reservation |
| Elevation via Stopbar compromise | Decision key | HSM/enclave, isolated account, co-signer mode |

## 15. Corpus format

See [`corpus/schema.json`](../corpus/schema.json). Each attack:

```yaml
id: CS-2026-0001
title: Encoded on-chain instruction drives agent transfer (Grok/Bankr pattern)
category: prompt_injection.encoded
target: agent_wallet.evm
references: ["https://…"]
setup:
  allowlist: ["0x1111…"]
  balances: {DRB: "100000"}
request:            # ActionRequest fixture (provenance included)
  …
expected:
  outcome: deny
  policy_ids: ["taint-unknown-destination"]
```

Replay harness: loads bundle, seeds limiter/registry from `setup`, evaluates `request`, asserts `expected`. Runs in CI on every PR to policies or engine.

## 16. Testing strategy

| Layer | Approach |
|---|---|
| Unit | Table tests per package |
| Limiter | Property tests (concurrency, rollover), Jepsen-lite with Redis failover |
| Decoder | Go native fuzzing on calldata; differential vs. ethers.js decode |
| Policy | Replay corpus; golden decisions per bundle |
| E2E | Anvil (local EVM) + sample agent + gatekeeper; scripted attacks |
| Security | Threat-model review per phase; external audit before Phase 4 |

## 17. Configuration (`stopbar.yaml`)

```yaml
mode: gatekeeper            # advisory | gatekeeper | cosigner
tenant: acme
listen: 127.0.0.1:7777
store: {kind: bbolt, path: ./data/cs.db}
policy: {bundle: ./policies, cooling_off_loosen: 24h, activation_quorum: 1}
contact_cooling_off: 24h    # destination-registry additions: approval -> active (CS-134; stopbard -contact-cooling-off)
limits:                     # internal/limiter Rule; window ∈ 1m | 1h | 24h | tx (per transaction)
  - {scope: wallet, window: tx, max_usd: "2500", max_pct_of_balance: "0.5"}   # hard per-tx caps (CS-123)
  - {scope: wallet, window: 1h, max_usd: "5000", max_count: 50}
  - {scope: wallet+asset, window: 24h, max_units: "1000000000000000000000000"}   # raw units; holds with no price
  - {scope: destination, window: 24h, max_count: 5, unknown_destinations_only: true, escalate: true}   # salami soft cap
  - {scope: tenant, window: 1h, max_usd: "20000", circuit_breaker: true}   # reset: -breaker-quorum approvers (CS-124)
max_slippage: "0.03"        # excessive_slippage threshold (fraction of the swap's value)
prices: {sources: [chainlink, coingecko], staleness: 15s}
decision_key: {provider: local, path: ./keys/decision.ed25519}
signer: {adapter: local, keystore: ./keys/agent-wallet.json}
escalation: {approvers: ["ed25519:…"], quorum: 1, timeout: 15m, channels: [cli]}
audit: {checkpoint_every: 1000, rekor: false}
```

### 17.1 `stopbar init` (CS-195, FR-DX-1/3)

`stopbar init [--persona agent-wallet] [--dir DIR] [--tenant T] [--agent ID] [--chain dev|base|base-sepolia] [--rpc URL] [--force]` writes one directory that `stopbard -config DIR/stopbard.json` runs as is. The config uses the current flag surface (`cmd/stopbard` `applyConfigFile`, JSON with snake_case flag names, absolute paths), not the target `stopbar.yaml` above.

- **Secure by default, never optional:** `listen` is `127.0.0.1:7777`, `auth_keys` is set (one `evaluate`-scoped key for `--agent`), `approvers` names two fresh Ed25519 approver keys whose owners are `approver-1`/`approver-2` (never the agent, so it cannot self-approve), `approval_quorum` and `breaker_quorum` are 2, `rate_per_min` is 600, and a fresh gatekeeper wallet (`dev_wallet`) makes it gatekeeper mode. `init` has no flag that weakens any of these.
- **Policies:** the persona's starter pack, embedded from `examples/policies` (`examples/policies/embed.go`), so the written bundle is that pack byte for byte. `agent-wallet` is the only persona.
- **World:** `limits` are `devstub.DefaultLimits` written out so they can be edited, `known_destinations` is empty, and the price/balance source is `--chain`: `dev` is static (1 ETH at $3,500, 1,000 USDC on Base, sized so the 20%-of-balance escalation fits under the $5,000/h wallet cap and an approval can execute), `base`/`base-sepolia` set `chain_rpc` (public RPC, or `--rpc`) and the Chainlink feeds the demos verified.
- **Secrets:** key files, configs and the key store are 0600, directories 0700 (`policies/` 0755). The API key secret is printed once and stored nowhere.
- **Overwrite:** any existing target fails the run, listing each file; `--force` removes and rewrites them (so modes are fresh). An existing `state/state.db` is refused even with `--force`: it holds the audit log signed with the old decision key.
- **Output:** what was written, the secret, and the exact next commands (start stopbard, SDK environment, `stopbar approve` with each approver key, `stopbar audit verify --decision-key`). `scripts/e2e_init.py` runs that journey in CI.

## 18. Research evaluation harness (Phase 1R)

Lives in `research/agentdojo/`. Python, pinned dependencies, one command per run. Talks to the same `stopbard` binary over `/v1/evaluate`; no Python re-implementation of policy.

### 18.1 Defence adapter

AgentDojo lets a defence intercept every tool call before execution. The adapter:

1. Converts the call to `ActionRequest{action.kind: "tool_call", tool, args}` with a fresh nonce and the session's `provenance.labels`.
2. Labels inputs: user prompt → `trusted_user`; every tool output → `tool_output`; tool outputs from AgentDojo's injectable fields (emails, web pages, files, reviews) → additionally `untrusted_email` / `untrusted_web` / `untrusted_file`. Context-level taint (§8.2): labels accumulate for the session.
3. Calls the LLM monitor with the transcript so far + the proposed call (§18.3).
4. Applies the arm's rule (§18.2). A block returns a tool error string containing Stopbar's reason codes, so the agent can recover and the adaptive attacker can learn from it.

### 18.2 Arms

| Arm | Enforcer | Shadow-logged |
|---|---|---|
| A0 none | — | policy + monitor |
| A1 monitor | LLM monitor | policy |
| A2 stopbar | policy (deny and escalate both block; escalate counted separately) | monitor |
| A3 both | block if either blocks | — (both enforce) |

### 18.3 LLM monitor

- Input: system prompt (versioned in `research/agentdojo/prompts/monitor_v1.md`), transcript, proposed call.
- Output: `{"verdict": "allow"|"block", "score": 0-100, "rationale": str}`; block threshold fixed before runs, chosen on a held-out calibration split.
- Two monitor models: one frontier, one open-weight. Model IDs pinned in the run config.

### 18.4 Tool-call policy pack

Tool-call bundles (CS-502) carry a `tool-trust.json`, hashed with the policies, that classifies every tool as read-only or state-changing and marks untrusted-output and account-identity tools. Undeclared tools fail closed. Cedar sees principal `Agent`, action `tool_call`, resource `Tool::<name>` and context `{state_changing, account_identity, taint}`. **Session taint is computed by Stopbar** (`policy.SessionTaint`, keyed by tenant, agent and `actor.session_id`, which is required) from the same file: a session is tainted once it evaluates a call to an untrusted-output tool. The pilot pack lives in `research/agentdojo/policies/banking/`. Originally proposed: `examples/policies/agentdojo.cedar`, with context adding `tool: String`, `recipient_external: Bool`, `amount: decimal?`, `taint: Set<String>`. Starter rules: deny state-changing tools (`send_email`, `send_money`, `update_password`, `share_file`, …) to non-allowlisted recipients while untrusted taint is present; escalate any money movement above the suite's per-task cap. Policy written **before** looking at injection tasks; frozen bundle hash recorded per run.

### 18.5 Shadow log (JSONL, one line per tool call)

```json
{"run_id":"…","arm":"A2","suite":"banking","user_task":"user_task_3","injection_task":"injection_task_1",
 "attack":"important_instructions","step":4,"tool":"send_money","args_hash":"sha256:…",
 "taint":["tool_output","untrusted_file"],
 "policy":{"outcome":"deny","policy_ids":["taint-external-recipient"],"latency_ms":3.1},
 "monitor":{"verdict":"allow","score":22,"latency_ms":840},
 "enforced":"block","policy_bundle_hash":"sha256:…","monitor_model":"…","agent_model":"…","seed":7}
```

### 18.6 Metrics

| Metric | Definition |
|---|---|
| Benign utility | % user tasks solved, no injection |
| Utility under attack | % user tasks solved with an injection present |
| ASR | % (user task, injection task) pairs where the injection goal is achieved |
| Disagreement matrix | Over attack-attempt calls: policy-only block / monitor-only block / both / neither |
| Adaptive ASR | ASR when the attacker sees the policy bundle and gets up to N=10 attempts with denial reasons |
| T4 containment | % SHADE-style side tasks completed under A2 vs A0 |

95% CIs by bootstrap over task pairs. Report latency per arm.

### 18.7 Adaptive attacker and T4 setting

- **Adaptive:** an attacker LLM receives the policy text, the user task and prior denial reasons, and rewrites the injection. Explicitly tries known bypasses: routing through allowlisted recipients, splitting amounts below caps, using a non-gated tool to the same effect.
- **T4 (scheming agent):** the agent's system prompt contains a covert side task (e.g. move funds to an external account), with the user task as cover. No injection needed. Measures what policy contains when the agent itself is the adversary and harness taint is honest-but-irrelevant.

### 18.8 Reproducibility

`make eval ARM=A2 SUITE=banking SEED=7` reproduces a run. Each results folder stores the run config, policy bundle, prompts, model IDs, AgentDojo version and raw JSONL.
