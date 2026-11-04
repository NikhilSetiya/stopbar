# Countersign — Low-Level Design

| | |
|---|---|
| Version | 0.2 (draft) |
| Date | 2026-11-04 |
| Related | [PRD](PRD.md) · [HLD](HLD.md) · [TASKS](TASKS.md) |

---

## 1. Repository layout

```
countersign/
├── cmd/
│   ├── countersignd/        # service / sidecar binary
│   └── countersign/         # CLI
├── internal/
│   ├── gateway/             # HTTP API, authN, nonce/TTL
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

```go
type Engine interface {
    Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error)
    Commit(ctx context.Context, requestID string, txRef string) error
    Release(ctx context.Context, requestID string) error
}

type Decoder interface {
    Supports(a model.Action) bool
    Decode(ctx context.Context, a model.Action) (model.IntentSummary, error)
}

type Enricher interface {
    Enrich(ctx context.Context, req *model.EnrichedRequest) error // must set staleness markers
}

type Limiter interface {
    Snapshot(ctx context.Context, keys []limiter.Key) (limiter.Counters, error)
    Reserve(ctx context.Context, id string, keys []limiter.Key, amt limiter.Amount, ttl time.Duration) error // ErrCapExceeded
    Commit(ctx context.Context, id string) error
    Release(ctx context.Context, id string) error
}

type DecisionSigner interface {
    Sign(ctx context.Context, d model.Decision) (model.SignedDecision, error)
    PublicKeys() []jose.JSONWebKey
}

type SignerAdapter interface {        // gatekeeper mode
    SignTx(ctx context.Context, sd model.SignedDecision, tx []byte) ([]byte, error) // must verify sd first
}

type AuditLog interface {
    Append(ctx context.Context, rec model.AuditRecord) (model.AuditReceipt, error)
    Verify(ctx context.Context, from, to uint64) error
}
```

Every component returns typed errors; the engine maps any non-domain error to `deny` with `FAIL_CLOSED_<component>` (§12).

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
    "sdk": {"name": "countersign-ts", "version": "0.1.0"}
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
  "payload_hash": "keccak256:…"
}
```

### 3.3 EnrichedRequest (policy context)

| Field | Type | Source |
|---|---|---|
| `amount_usd` | decimal | price oracle; `null` + `price_stale=true` if stale |
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
  "reasons": [{"policy_id": "taint-unknown-destination", "message": "Untrusted on-chain content in context; destination not allowlisted"}],
  "policy_bundle_hash": "sha256:…",
  "payload_hash": "keccak256:…",
  "approvals": [],
  "reservation_id": null,
  "issued_at": "…",
  "expires_at": "…"                         // = issued_at + 60s default
}
```

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
- Checks in order: auth → JSON schema → `issued_at` within ±30s clock skew → TTL ≤ 300s → nonce unseen (nonce store TTL = max TTL) → body size ≤ 64 KB.
- Per-requester API rate limit (token bucket) protects availability, separate from value limiter.

### 4.1 API

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/evaluate` | Evaluate an ActionRequest. Returns Decision (+ signed tx in gatekeeper mode). `202` with `escalation_id` when escalated. |
| GET | `/v1/decisions/{request_id}` | Poll decision (for escalations) |
| POST | `/v1/actions/{request_id}/commit` | Report broadcast tx hash → commit reservation |
| POST | `/v1/actions/{request_id}/release` | Abandon → release reservation |
| POST | `/v1/approvals/{escalation_id}` | Submit signed approval |
| POST | `/v1/events/deploy` | Ingest deploy/change event (Phase 4) |
| GET | `/v1/audit?from=&to=` | Export audit range |
| GET | `/v1/keys` | JWKS of decision-signing keys |
| GET | `/healthz`, `/metrics` | Ops |

Error body: `{"code": "NONCE_REPLAYED", "message": "…", "request_id": "…"}`.

## 5. Policy engine

### 5.1 Cedar schema (excerpt)

```cedar
namespace Countersign {
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

Cedar natively yields permit/forbid. Countersign layers **escalate** via annotations:

- `@outcome("deny")` on `forbid` policies → deny.
- `@outcome("escalate")` on `forbid` policies → escalate (only if no deny matched).
- At least one `permit` must match, otherwise deny (default-deny).

Combination: `deny > escalate > allow`. Evaluate escalate-annotated policies as a separate Cedar policy set so "forbid" in that set means escalate.

### 5.3 Example policy (`examples/policies/agent-wallet.cedar`)

```cedar
@id("base-permit")
permit (principal, action in [Countersign::Action::"transfer", Countersign::Action::"contract_call"], resource);

@id("taint-unknown-destination") @outcome("deny")
forbid (principal, action, resource)
when { context.taint.containsAny(["untrusted_web","untrusted_onchain","untrusted_email"]) && !context.dest_known };

@id("unlimited-approval") @outcome("deny")
forbid (principal, action == Countersign::Action::"approve", resource)
when { context.flags.contains("unlimited_approval") };

@id("delegatecall") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("delegatecall") };

@id("large-share-of-balance") @outcome("escalate")
forbid (principal, action, resource) when { context.pct_of_balance > decimal("0.20") };

@id("address-poisoning") @outcome("escalate")
forbid (principal, action, resource) when { context.dest_similar_to_known && !context.dest_known };

@id("stale-price") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };
```

### 5.4 Bundles

- A bundle = policies + schema + limiter config + allowlists. Identified by `sha256` over a sorted tar.
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

### 7.4 Properties to test

- No interleaving of concurrent `Reserve` exceeds any cap (property test with 1,000 goroutines).
- Expired reservations always released.
- Window rollover never double-counts or drops.

## 8. Provenance and taint

### 8.1 Labels

`trusted_user`, `trusted_system`, `tool_output`, `untrusted_web`, `untrusted_onchain`, `untrusted_email`, `untrusted_file`, `decoded`, `sensitive_internal` (Phase 3).

### 8.2 v1 — context-level taint (SDK)

```ts
const cs = new Countersign({ endpoint, agentId });
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
2. Channel adapters push the rendered intent. Phase 1: CLI (`countersign approve <id>`) signing with an Ed25519 approver key; Phase 2: Slack/Telegram with deep link to a signing page; Phase 4: WebAuthn passkeys.
3. Approval payload = `{escalation_id, payload_hash, decision: approve|reject, ts}` signed by approver key. Engine verifies signer ∈ approvers, payload_hash matches, not expired, no duplicates.
4. Any `reject` → deny. Timeout (default 15m) → deny.

## 10. Decision tokens and countersignatures

### 10.1 JWS (gatekeeper / generic)

- Algorithm: EdDSA (Ed25519). Header `kid` maps to `/v1/keys`.
- Claims: `request_id`, `payload_hash`, `outcome`, `policy_bundle_hash`, `iat`, `exp`, `nonce`, `tenant`.
- Signer adapters **must** verify the JWS and that `payload_hash` equals the hash of the tx they are about to sign.

### 10.2 EIP-712 (co-signer, Phase 4)

```
Countersignature(address safe, bytes32 txHash, uint256 nonce, uint64 expiry, bytes32 policyBundle)
domain: {name: "Countersign", version: "1", chainId, verifyingContract: guard}
```

`CountersignGuard` (Safe Guard) `checkTransaction` requires a valid secp256k1 signature from the configured Countersign address over the struct. Guard keeps `usedNonces`.

### 10.3 Key providers

`local` (file, dev only — refuses to start in `--mode=prod`), `awskms`, `pkcs11` (HSM, Phase 4), `nitro` (enclave, Phase 4).

## 11. Audit log

- Store: append-only table/bucket keyed by `seq`. No update/delete paths in code; DB role has INSERT/SELECT only.
- Every request, decision, approval, policy change, commit, release, override appended in the same transaction as the state change it records (outbox pattern for Redis-backed limiter).
- Checkpoint every N=1,000 records or 5 minutes: Merkle root over the range signed by the decision key; optional upload to Rekor.
- `countersign audit verify --from X --to Y` recomputes hashes and validates checkpoint signatures.

## 12. Error handling (fail closed)

| Code | When | Outcome |
|---|---|---|
| `FAIL_CLOSED_DECODER` | Decoder panic/error | deny |
| `FAIL_CLOSED_ENRICH` | Enricher timeout | deny (or escalate if configured for price staleness) |
| `FAIL_CLOSED_LIMITER` | Store unavailable | deny |
| `FAIL_CLOSED_POLICY` | No active bundle / eval error | deny |
| `FAIL_CLOSED_AUDIT` | Audit append fails | deny (no unaudited decisions) |
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
| Elevation via Countersign compromise | Decision key | HSM/enclave, isolated account, co-signer mode |

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

## 17. Configuration (`countersign.yaml`)

```yaml
mode: gatekeeper            # advisory | gatekeeper | cosigner
tenant: acme
listen: 127.0.0.1:7777
store: {kind: bbolt, path: ./data/cs.db}
policy: {bundle: ./policies, cooling_off_loosen: 24h, activation_quorum: 1}
limits:
  - {scope: wallet, window: 1h, max_usd: 5000, max_count: 50}
  - {scope: tenant, window: 1h, max_usd: 20000, circuit_breaker: true}
prices: {sources: [chainlink, coingecko], staleness: 15s}
decision_key: {provider: local, path: ./keys/decision.ed25519}
signer: {adapter: local, keystore: ./keys/agent-wallet.json}
escalation: {approvers: ["ed25519:…"], quorum: 1, timeout: 15m, channels: [cli]}
audit: {checkpoint_every: 1000, rekor: false}
```

## 18. Research evaluation harness (Phase 1R)

Lives in `research/agentdojo/`. Python, pinned dependencies, one command per run. Talks to the same `countersignd` binary over `/v1/evaluate`; no Python re-implementation of policy.

### 18.1 Defence adapter

AgentDojo lets a defence intercept every tool call before execution. The adapter:

1. Converts the call to `ActionRequest{action.kind: "tool_call", tool, args}` with a fresh nonce and the session's `provenance.labels`.
2. Labels inputs: user prompt → `trusted_user`; every tool output → `tool_output`; tool outputs from AgentDojo's injectable fields (emails, web pages, files, reviews) → additionally `untrusted_email` / `untrusted_web` / `untrusted_file`. Context-level taint (§8.2): labels accumulate for the session.
3. Calls the LLM monitor with the transcript so far + the proposed call (§18.3).
4. Applies the arm's rule (§18.2). A block returns a tool error string containing Countersign's reason codes, so the agent can recover and the adaptive attacker can learn from it.

### 18.2 Arms

| Arm | Enforcer | Shadow-logged |
|---|---|---|
| A0 none | — | policy + monitor |
| A1 monitor | LLM monitor | policy |
| A2 countersign | policy (deny and escalate both block; escalate counted separately) | monitor |
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
