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
│   ├── enrich/              # price, balance, velocity snapshot, provenance, deploy age
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
Commit(ctx, requestID, txRef string) error
Release(ctx, requestID string) error

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
    Reserve(ctx, id string, req model.EnrichedRequest, ttl time.Duration) error // ErrCapExceeded, ErrCircuitOpen
    Commit(ctx, id, txRef string) error
    Release(ctx, id string) error // idempotent; no-op for unknown id
}
type Signer interface {
    Sign(ctx, d model.Decision) (token string, err error) // spec/decision-token-v1.md
}
type AuditLog interface {
    Append(ctx, typ model.AuditRecordType, body any) error
}
```

Pipeline: **normalize** (bind `payload_hash`, decision-token-v1 §2) → **decode** (first decoder that `Supports`) → **enrich** → **policy** → **limiter** (allow only) → **sign** (allow only) → **audit** (every decision).

- Every component call runs with a stage timeout (default 1 s) and panic recovery. A component that ignores `ctx` is abandoned, and its partial output is never read.
- The engine enforces invariants between stages:
  - The decoder may not render a payload other than the bound one.
  - Enrichers may not change the action or intent, and may not remove a provenance label from `taint`.
  - The policy result must have a known outcome, reasons for deny or escalate, and a valid bundle hash.
- Only allow reserves limiter capacity and gets a token. Escalations do not reserve: approval (CS-151) re-runs the limiter, so pending escalations cannot tie up caps.
- If anything fails after the reservation, the reservation is released. If the audit append fails, an allow becomes a deny and the token is discarded.
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
  "payload_hash": "sha256:…"
}
```

### 3.3 EnrichedRequest (policy context)

| Field | Type | Source |
|---|---|---|
| `amount_usd` | decimal | price oracle; `null` + `price_stale=true` if stale. **Decided (CS-131):** `amount_usd` becomes optional in the schema (`amount_usd?`), so a stale price reaches the `stale-price` escalate policy. This is safe: a policy that reads it without `context has amount_usd` errors, and errors deny. Token-count caps still apply without a price. The rendered intent must say "price unavailable", never $0. Until CS-131 the schema requires it, so a stale price currently denies. |
| `pct_of_balance` | decimal | balance provider |
| `velocity.{1m,1h,24h}.usd` / `.count` | decimal/int | limiter snapshot |
| `destination.known` | bool | destination registry |
| `destination.similar_to_known` | bool | address-similarity check |
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
  "token": "…"                              // allow only: decision token (spec/decision-token-v1.md)
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
| GET | `/v1/decisions/{request_id}` | Poll decision (for escalations) |
| POST | `/v1/actions/{request_id}/commit` | Report broadcast tx hash → commit reservation |
| POST | `/v1/actions/{request_id}/release` | Abandon → release reservation |
| POST | `/v1/approvals/{escalation_id}` | Submit signed approval |
| POST | `/v1/events/deploy` | Ingest deploy/change event (Phase 4) |
| GET | `/v1/audit?from=&to=` | Export audit range |
| GET | `/v1/keys` | JWKS of decision-signing keys |
| GET | `/healthz`, `/metrics` | Ops |

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
| `ENGINE_UNAVAILABLE` | 503 | No engine configured |
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

1. Native value transfer if `data` empty.
2. Selector lookup: built-in table (ERC-20/721/1155, Permit2, Safe `execTransaction`, multicall variants) → local 4byte DB fallback.
3. Recursive decode for multicall / Safe inner txs (max depth 4; deeper → flag `opaque`).
4. Unknown selector → flag `unknown_call` (policy decides; default escalate).

### 6.2 Risk flags

| Flag | Rule |
|---|---|
| `unlimited_approval` | approve/permit amount ≥ 2^255 or ≥ 10× balance |
| `delegatecall` | Safe op = 1, or known delegatecall patterns |
| `proxy_upgrade` | `upgradeTo*`, `changeMasterCopy`, implementation slot writes |
| `new_destination` | destination absent from tenant registry |
| `similar_destination` | same first 4 + last 4 hex chars as a known destination but different address |
| `first_time_contract` | contract never interacted with by this wallet |
| `opaque` | nesting > depth or undecodable inner call |
| `min_out_zero` | known swap selector (Uniswap V2/V3 routers, Universal Router, 1inch, 0x) with `amountOutMin` / `minReturn` = 0 |
| `excessive_slippage` | swap minimum output below quoted output × (1 − tenant max slippage, default 3%) |
| `unknown_call` | selector unknown |

### 6.3 Human rendering

Template per `kind`, amounts formatted with decimals and USD, addresses shortened `0x9f3…c21` **plus** a 6-word checksum phrase derived from the full address (defeats visual look-alike). The rendered text and `payload_hash` are sent together; approvals sign over `payload_hash`.

## 7. Limiter

### 7.1 Keys and windows

Key = `(tenant, scope, id, window)` where scope ∈ {`agent`, `wallet`, `wallet+asset`, `destination`, `tenant`}. `destination` scope carries a `max_count` by default (e.g. 5 per 24h for non-allowlisted destinations) so salami draining below per-tx caps is bounded. Windows: 1m, 1h, 24h (configurable).

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
  - Commit or release of an unknown ID returns `ErrUnknownReservation`, and of a lapsed one `ErrReservationExpired`.
  - **A late commit still records the spend**, so loss bounding counts what actually happened.
  - The engine treats unknown or expired IDs on its own best-effort release as "nothing held".
- **Keys** quote each component, so requester-chosen tenant or agent IDs can't collide. Agent and tenant scopes are only as strong as authentication (CS-103), while wallet scopes are bound to the signing address.
- **Velocity:** the limiter is also an `Enricher`. It supplies `velocity.{1m,1h,24h}` (committed + reserved, wallet scope) to policy.
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
- `decoded` is added automatically if the SDK detects encoded content (base64, hex, Morse, ROT-n, zero-width chars) in untrusted inputs.
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

1. Engine creates `Escalation{id, request_id, intent, payload_hash, required: M, approvers: [..], expires_at}`.
2. Channel adapters push the rendered intent. Phase 1: CLI (`stopbar approve <id>`) signing with an Ed25519 approver key; Phase 2: Slack/Telegram with deep link to a signing page; Phase 4: WebAuthn passkeys.
3. Approval payload = `{escalation_id, payload_hash, decision: approve|reject, ts}` signed by approver key. Engine verifies signer ∈ approvers, payload_hash matches, not expired, no duplicates.
4. Any `reject` → deny. Timeout (default 15m) → deny.
5. **Approval re-evaluates against current state.** It does not replay the old decision. When quorum is reached, the engine re-runs **enrich → policy → limiter → sign** for the same request and `payload_hash`, with the verified approvals as a policy input (`context.approvals`: count and approver IDs). An escalation can wait up to 15 minutes, and in that time prices move, velocity windows fill and the circuit breaker can trip. A human approves the world as it was, but the system signs into the world as it is. The re-run can therefore still deny (for example `CAP_EXCEEDED`, or a deny policy that now matches) or escalate again. Policies decide what an approval satisfies: an escalate policy is written as `forbid … when { … && context.approvals.count < 1 }`, while deny policies ignore approvals. The resulting decision gets a fresh `iat`/`exp` and is audited as its own record, linked to the escalation.

## 10. Decision tokens and countersignatures

### 10.1 JWS (gatekeeper / generic)

Normative spec: [`spec/decision-token-v1.md`](../spec/decision-token-v1.md), with vectors in `spec/vectors/decision-token-v1.json`.

- Algorithm: EdDSA (Ed25519). The header is exactly `{alg, kid, typ}`, and `kid` is the RFC 7638 thumbprint of a key pinned from `/v1/keys`.
- Claims (closed set, JCS-canonical): `v`, `iss`, `aud`, `tenant`, `request_id`, `nonce`, `outcome`, `payload_hash`, `policy_bundle_hash`, `reservation_id`, `iat`, `exp`.
- `payload_hash` = sha256 over JCS of the normalised action (spec §2), not a chain tx hash. Gas, nonce and fees are adapter-chosen and capped.
- Signer adapters **must** run the spec §4 checks in order. The checks include recomputing `payload_hash` from the tx they are about to sign, and single use per `(iss, tenant, nonce)`.

### 10.2 EIP-712 (co-signer, Phase 4)

```
Countersignature(address safe, bytes32 txHash, uint256 nonce, uint64 expiry, bytes32 policyBundle)
domain: {name: "Stopbar", version: "1", chainId, verifyingContract: guard}
```

`StopbarGuard` (Safe Guard) `checkTransaction` requires a valid secp256k1 signature from the configured Stopbar address over the struct. Guard keeps `usedNonces`.

### 10.3 Key providers

`local` (file, dev only — refuses to start in `--mode=prod`), `awskms`, `pkcs11` (HSM, Phase 4), `nitro` (enclave, Phase 4).

## 11. Audit log

- Store: append-only table/bucket keyed by `seq`. No update/delete paths in code; DB role has INSERT/SELECT only.
- Every request, decision, approval, policy change, commit, release, override appended in the same transaction as the state change it records (outbox pattern for Redis-backed limiter).
- Checkpoint every N=1,000 records or 5 minutes: Merkle root over the range signed by the decision key; optional upload to Rekor.
- `stopbar audit verify --from X --to Y` recomputes hashes and validates checkpoint signatures.

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
| `CIRCUIT_OPEN` | Breaker tripped | deny |
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
limits:                     # internal/limiter Rule; window ∈ 1m | 1h | 24h
  - {scope: wallet, window: 1h, max_usd: "5000", max_count: 50}
  - {scope: wallet+asset, window: 24h, max_units: "1000000000000000000000000"}   # raw units; holds with no price
  - {scope: destination, window: 24h, max_count: 5, unknown_destinations_only: true}
  - {scope: tenant, window: 1h, max_usd: "20000", circuit_breaker: true}
prices: {sources: [chainlink, coingecko], staleness: 15s}
decision_key: {provider: local, path: ./keys/decision.ed25519}
signer: {adapter: local, keystore: ./keys/agent-wallet.json}
escalation: {approvers: ["ed25519:…"], quorum: 1, timeout: 15m, channels: [cli]}
audit: {checkpoint_every: 1000, rekor: false}
```

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

`examples/policies/agentdojo.cedar`. Context adds `tool: String`, `recipient_external: Bool`, `amount: decimal?`, `taint: Set<String>`. Starter rules: deny state-changing tools (`send_email`, `send_money`, `update_password`, `share_file`, …) to non-allowlisted recipients while untrusted taint is present; escalate any money movement above the suite's per-task cap. Policy written **before** looking at injection tasks; frozen bundle hash recorded per run.

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
