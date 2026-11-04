# Countersign — Build Backlog

> Generated from `scripts/tasks.py`. Edit there, then run `python3 scripts/tasks.py`.

Estimates are focused build days for one engineer. IDs are stable; reference them in commits (`CS-122: …`).

## Summary

| Phase | Tasks | Est. days |
|---|---|---|
| Phase 0 - Foundations (weeks 0-2) | 9 | 9 |
| Phase 1 - Agent-wallet MVP (weeks 2-8) | 41 | 71 |
| Phase 1R - Research track (parallel, weeks 4-10) | 11 | 21.5 |
| Phase 2 - Corpus & community (weeks 8-12) | 6 | 12.5 |
| Phase 3 - Code-mode agents (months 3-9) | 7 | 35 |
| Phase 4 - Custody grade (year 2) | 8 | 65 |

## Capacity reality

Phase windows assume full-time focus. Part-time (~12 h/week) multiplies calendar time by ~3x.
Ship the **thin slice** first: the minimum path to a public demo where Countersign blocks the seed attacks against an EVM agent wallet.

**Thin slice: 23 tasks, ~41 build days** — CS-001, CS-002, CS-003, CS-005, CS-006, CS-101, CS-104, CS-111, CS-112, CS-113, CS-121, CS-133, CS-122, CS-141, CS-142, CS-161, CS-162, CS-171, CS-181, CS-183, CS-191, CS-192, CS-193

Everything else in Phase 1 hardens or widens the slice after it's public.

## Phase 0 - Foundations (weeks 0-2)

### E0 Foundations

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-001 | Create GitHub repo, license, README, docs | Public repo, Apache-2.0, README, PRD/HLD/LLD/TASKS committed. | Repo public; docs render; LICENSE detected by GitHub. | 0.5d |  |  |
| CS-002 | Go module + repo layout | Create Go module and directory layout per LLD §1 with placeholder packages. | `go build ./...` passes; layout matches LLD. | 0.5d | CS-001 |  |
| CS-003 | CI pipeline | GitHub Actions: lint (golangci-lint), test, race detector, govulncheck, build on PR. | PR shows green checks; failing test blocks merge. | 1d | CS-002 |  |
| CS-004 | Supply-chain hygiene | Dependabot, pinned action SHAs, SECURITY.md, CODEOWNERS, branch protection. | Branch protection on main; Dependabot PRs appear. | 0.5d | CS-003 | NFR-7 |
| CS-005 | Core data model | Implement ActionRequest, IntentSummary, EnrichedRequest, Decision, AuditRecord structs + JSON schema in spec/. | Round-trip JSON tests; schemas validate fixtures. | 2d | CS-002 | LLD §3 |
| CS-006 | JCS canonicalisation + hashing utils | RFC 8785 canonical JSON; payload_hash and record hash helpers. | Matches RFC 8785 test vectors. | 1d | CS-005 | LLD §3.5 |
| CS-007 | Cedar spike | Prototype cedar-go with Countersign schema; validate decimal/set context and escalate-annotation approach. | Spike doc in docs/adr/0001-cedar.md with go/no-go. | 2d | CS-005 | PRD §13 Q1 |
| CS-008 | Decision token spec | Write spec/decision-token-v1.md (JWS claims, payload binding, expiry, nonce). | Spec merged; test vectors included. | 1d | CS-006 | LLD §10.1 |
| CS-009 | ADR log | docs/adr with ADRs: enforcement modes, Go, Cedar, fail-closed. | 4 ADRs merged. | 0.5d | CS-001 |  |

## Phase 1 - Agent-wallet MVP (weeks 2-8)

### E1 Gateway & engine

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-101 | HTTP gateway skeleton | /v1/evaluate, /healthz, /metrics; JSON schema validation; size limits. | Invalid requests 400 with typed code; tests. | 2d | CS-005 | FR-INT-1 |
| CS-102 | Nonce + TTL checks | Nonce store (bbolt) with TTL; clock-skew window. | Replayed nonce -> NONCE_REPLAYED; expired -> EXPIRED. | 1d | CS-101 | FR-INT-4 |
| CS-103 | API key auth (dev) + mTLS option | API key for sidecar; mTLS with client cert identity for service mode. | Unauthenticated -> 401; identity propagated to actor. | 1.5d | CS-101 |  |
| CS-104 | Engine orchestration | Pipeline normalize->decode->enrich->policy->limiter->sign->audit with fail-closed mapping. | Any component error -> deny with FAIL_CLOSED_*; panic recovered. | 3d | CS-101 | LLD §2, §12 |
| CS-105 | Commit/release endpoints | /v1/actions/{id}/commit and /release wired to limiter. | Reservation lifecycle e2e test passes. | 1d | CS-104,CS-122 |  |

### E2 Policy

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-111 | Cedar schema + loader | Load .cedar files + schema; validate; compute bundle hash. | Invalid policy rejected with line number; hash stable across file order. | 2d | CS-007 | FR-POL-1 |
| CS-112 | Outcome combiner | Deny/escalate/allow via @outcome annotations; default deny; reasons list. | Table tests for all combinations. | 1.5d | CS-111 | FR-POL-2,3 |
| CS-113 | Starter policy pack | examples/policies/agent-wallet.cedar per LLD §5.3. | All seed corpus attacks get expected outcome. | 1d | CS-112 |  |
| CS-114 | Policy dry-run | `countersign policy test` against corpus + recorded requests. | Diff of outcomes printed; non-zero exit on regression. | 1.5d | CS-112,CS-192 | FR-POL-4 |
| CS-115 | Activation + cooling-off | Signed activation; loosening caps delayed by configurable period. | Loosening change inactive until delay passes; audited. | 2d | CS-111,CS-151 | FR-POL-5 |

### E3 Limiter

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-121 | Sliding-window counters | Sub-bucket windows for {usd,count} per scope key (bbolt impl). | Rollover tests pass; no double count. | 2d | CS-005 | FR-LIM-2 |
| CS-122 | Reserve/commit/release | Atomic reservations with TTL and janitor. | Property test: 1,000 concurrent reserves never exceed cap. | 2.5d | CS-121 | FR-LIM-4 |
| CS-123 | Per-tx and % balance caps | Absolute and pct_of_balance caps via policy context + limiter config. | OpenClaw fixture escalates. | 1d | CS-122,CS-133 | FR-LIM-1 |
| CS-124 | Circuit breaker | Tenant outflow breaker; M-of-N reset via CLI. | Breach -> CIRCUIT_OPEN until reset; alert metric emitted. | 1.5d | CS-122 | FR-LIM-3 |

### E4 Enrichment

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-131 | Price oracle client | Chainlink + CoinGecko with staleness bound and cache. | Stale -> price_stale=true; tests with fake clock. | 2d | CS-104 | FR-LIM-5 |
| CS-132 | Balance provider | RPC balance reads (native + ERC-20) with cache. | Anvil test returns correct balances. | 1d | CS-104 |  |
| CS-133 | Destination registry | Known destinations per tenant; similarity check (prefix/suffix). | Poisoned address flagged similar_to_known. | 1.5d | CS-104 | FR-IR-2 |

### E5 Decoder & intent

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-141 | EVM decoder core | Native, ERC-20/721/1155, Permit2, multicall, Safe execTransaction; recursion depth 4. | Golden tests for each type. | 3d | CS-005 | FR-IR-1 |
| CS-142 | Risk flags | unlimited_approval, delegatecall, proxy_upgrade, new/similar destination, first_time_contract, opaque, unknown_call. | Each flag has positive + negative test. | 2d | CS-141,CS-133 | FR-IR-2 |
| CS-143 | Human renderer + checksum phrase | Plain-language template + 6-word address checksum. | Snapshot tests; look-alike addresses yield different phrases. | 1.5d | CS-142 | FR-IR-3 |
| CS-145 | Destructive-action flags + salami caps | min_out_zero and excessive_slippage flags for known swap routers; default per-destination count cap for non-allowlisted destinations. | Zero-min-out swap fixture denied; 6 sub-cap transfers to new destination escalate. | 1.5d | CS-142,CS-121 | FR-IR-2, FR-LIM-2a |
| CS-144 | Decoder fuzzing | Go native fuzz targets on calldata. | 24h fuzz run with no panics. | 1d | CS-141 |  |

### E6 Escalation

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-151 | Approver keys + CLI approvals | Ed25519 approver keys; `countersign approve/reject <id>` signs over payload_hash. | Wrong hash or key rejected; quorum honoured. | 2d | CS-104 | FR-ESC-1,2 |
| CS-152 | Escalation lifecycle | Create, poll (/v1/decisions), timeout -> deny, reject -> deny. | E2E: escalate -> approve -> signed tx returned. | 1.5d | CS-151 | FR-ESC-3 |

### E7 Decision & signer

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-161 | Decision signer (JWS Ed25519) | Sign decisions; JWKS endpoint; local key provider (dev-only guard). | Tokens verify with published JWKS; prod mode refuses local key. | 1.5d | CS-008 | LLD §10 |
| CS-162 | Gatekeeper local signer adapter | Holds agent keystore; verifies decision token + payload_hash before signing. | Signing without valid token impossible (test). | 2d | CS-161 | FR-INT-3 |
| CS-163 | AWS KMS signer + decision key | KMS secp256k1 for tx signing; KMS for decision key. | Integration test against KMS (or localstack). | 2d | CS-162 |  |
| CS-164 | Turnkey adapter | Gatekeeper via Turnkey API key held only by Countersign. | Sandbox org test passes. | 2d | CS-162 |  |

### E8 Audit

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-171 | Hash-chained log | Append-only bbolt bucket; record per event in same tx as state change. | Tampering one record fails verify. | 2d | CS-006 | FR-AUD-1 |
| CS-172 | Checkpoints + verify CLI | Signed Merkle checkpoints; `countersign audit verify`. | Verify passes clean log, fails tampered. | 1.5d | CS-171,CS-161 | FR-AUD-2,3 |

### E9 SDKs & provenance

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-181 | TypeScript SDK | Client, context API with labels, evaluate/commit/release, typed errors. | Example agent protected end-to-end. | 3d | CS-104 | FR-INT-1, FR-PRV-1,2 |
| CS-182 | Python SDK | Parity with TS SDK. | Same example in Python passes. | 2d | CS-181 |  |
| CS-183 | Encoding detector | Detect base64/hex/Morse/ROT-n/zero-width in untrusted inputs -> add 'decoded'. | Grok-pattern fixture labelled decoded. | 1d | CS-181 |  |
| CS-184 | Framework integrations | Wrappers for one agent framework + viem/ethers signer shim. | Drop-in signer replacement demo. | 2d | CS-181 |  |

### E10 Corpus & replay

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-191 | Corpus schema | corpus/schema.json finalized; validator CLI. | All seed attacks validate. | 1d | CS-005 | FR-COR-1 |
| CS-192 | Replay harness | Seed state from setup; evaluate; assert outcome + policy_ids; CI job. | CI fails when a policy regression unblocks an attack. | 2d | CS-191,CS-112 | FR-COR-2 |
| CS-193 | 10 seed attacks | Grok/Bankr encoded injection; Bankr unauthorised signing; OpenClaw over-transfer; unlimited approval; delegatecall (Bybit pattern); proxy upgrade; address poisoning; velocity drain; stale-price under-valuation; multicall-hidden transfer. | All 10 present and blocked/escalated as expected. | 3d | CS-192 |  |

### E11 DX & release

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-195 | CLI: init | `countersign init --persona agent-wallet` generates config + policies + keys. | Fresh machine to protected agent < 30 min (timed). | 1.5d | CS-113 | FR-DX-1,3 |
| CS-196 | Docker image + binaries | goreleaser; signed releases (cosign); SBOM. | Release artifacts signed and verifiable. | 1d | CS-003 | FR-DX-2, NFR-7 |
| CS-197 | Benchmarks | Latency/throughput benchmarks vs. NFR-1/2. | p99 < 25ms sidecar at 1k rps published in docs. | 1.5d | CS-104 |  |
| CS-198 | Quickstart + E2E demo | Anvil + sample agent + attack replay video/GIF. | Demo reproducible from README. | 1.5d | CS-195,CS-193 |  |

## Phase 1R - Research track (parallel, weeks 4-10)

### E15 Research eval

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-501 | Threat-tier ADR | docs/adr/0005-threat-tiers.md: T1-T4 definitions, harness-vs-model trust boundary, which controls hold per tier. | ADR merged; PRD §2.4 and HLD §8 reference it. | 0.5d | CS-009 | PRD §2.4 |
| CS-502 | Tool-call policy schema + AgentDojo pack | Cedar context for tool_call (tool, recipient_external, amount, taint); examples/policies/agentdojo.cedar written before viewing injection tasks. | Bundle validates; hash frozen and recorded. | 2d | CS-112 | LLD §18.4 |
| CS-503 | AgentDojo defence adapter | Python adapter: tool call -> ActionRequest -> /v1/evaluate; block returns tool error with reason codes. | Benign banking suite runs end-to-end through countersignd. | 3d | CS-101,CS-104,CS-502 | FR-EVAL-1, LLD §18.1 |
| CS-504 | Harness provenance labelling | Label user prompt, tool outputs and AgentDojo injectable fields; session-level taint. | Injected-field outputs carry untrusted_* labels in the shadow log. | 1.5d | CS-503 | LLD §18.1 |
| CS-505 | LLM monitor | Versioned monitor prompt; frontier + open-weight model; threshold set on held-out calibration split. | Monitor verdicts reproducible at temperature 0 on a fixed sample. | 1.5d | CS-503 | LLD §18.3 |
| CS-506 | Shadow logging | Record policy and monitor verdicts on every call in every arm (JSONL schema §18.5). | Schema-validated log; both verdicts present for 100% of calls. | 1d | CS-505 | FR-EVAL-3 |
| CS-507 | Four-arm runner | A0-A3 across suites, attacks, seeds; pinned run config; `make eval`. | Full matrix runs from one command; results folder reproducible. | 2d | CS-504,CS-506 | FR-EVAL-2,6 |
| CS-508 | Metrics + analysis | Benign utility, utility under attack, ASR, disagreement matrix, bootstrap CIs, latency per arm. | Notebook regenerates all tables/figures from raw JSONL. | 2d | CS-507 | PRD §9, LLD §18.6 |
| CS-509 | Adaptive attacker | Attacker LLM with policy text + denial reasons, N=10 attempts; tries allowlist routing, amount splitting, ungated tools. | Adaptive ASR reported per arm with examples of successful bypasses. | 3d | CS-507 | FR-EVAL-4 |
| CS-510 | Scheming-agent (T4) setting | Covert side task in agent system prompt with user task as cover; no injection. | T4 containment reported for A0 vs A2. | 3d | CS-507 | FR-EVAL-5 |
| CS-511 | Results write-up | Preliminary report: method, results, failure cases, limitations; reproducibility package. | Published (repo + LessWrong/arXiv); every number traceable to a run folder. | 2d | CS-508,CS-509,CS-510 | G6 |

## Phase 2 - Corpus & community (weeks 8-12)

### E12 Community

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-201 | Contribution flow for attacks | PR template, auto-validation, labels, CONTRIBUTING. | External contributor can add an attack without help. | 1.5d | CS-192 | FR-COR-3 |
| CS-202 | Docs site | MkDocs/Docusaurus from docs/; spec pages. | Site live via GitHub Pages. | 1.5d | CS-198 |  |
| CS-203 | Slack/Telegram escalation channels | Push rendered intent + signing link. | Approve from phone e2e. | 2d | CS-152 |  |
| CS-204 | Launch | Write-up of thesis + incident analysis; HN/X/LinkedIn; outreach to 20 agent builders. | Launch posted; metrics dashboard live. | 2d | CS-198,CS-202 |  |
| CS-205 | Design partners | Recruit 3 agent-wallet teams for shadow (advisory) mode. | 3 partners running advisory mode with feedback logged. | 5d | CS-204 |  |
| CS-206 | Kill/pivot review | Review month-3 metrics vs PRD §11. | Written decision: continue / pivot. | 0.5d | CS-205 | PRD §11 |

## Phase 3 - Code-mode agents (months 3-9)

### E13 Code-mode

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-301 | Binding wrapper runtime (TS) | Instrumented bindings for sandboxed scripts; each call -> ActionRequest(tool_call). | Script calls blocked by policy raise exception inside sandbox. | 5d | CS-181 | FR-PRV-5 |
| CS-302 | Field-level taint propagation | Tainted<T> wrappers + propagation through derived values. | Exfil fixture (crm.export -> email.send external) denied. | 8d | CS-301 | LLD §8.3 |
| CS-303 | Python binding runtime | Parity for Python sandboxes. | Same fixtures pass. | 5d | CS-302 |  |
| CS-304 | MCP gateway adapter | Enforce policy on MCP tool calls at a gateway. | MCP server calls evaluated with taint. | 5d | CS-301 |  |
| CS-305 | Static pre-execution checks | Flag loops over sensitive bindings feeding network calls before running. | Pre-check catches seeded exfil script. | 5d | CS-302 |  |
| CS-306 | Postgres + Redis store | Production stores; Lua reserve script. | Concurrency property tests pass on Redis. | 4d | CS-122 |  |
| CS-307 | Code-mode corpus | 10 attacks: loop exfil, injected script, tool chaining, etc. | All blocked. | 3d | CS-302 |  |

## Phase 4 - Custody grade (year 2)

### E14 Custody grade

| ID | Task | Detail | Acceptance criteria | Est | Depends | Refs |
|---|---|---|---|---|---|---|
| CS-401 | CountersignGuard (Safe Guard) | Solidity guard verifying EIP-712 countersignature + nonce. | Foundry tests; external audit scheduled. | 8d | CS-161 | LLD §10.2 |
| CS-402 | MPC share integration | Countersign as one share holder with an MPC provider. | Tx impossible without Countersign share in test. | 10d | CS-161 |  |
| CS-403 | HSM / Nitro Enclave decision key | PKCS#11 and enclave key providers; attestation. | Key never leaves HSM/enclave; attestation verified. | 8d | CS-161 | NFR-5 |
| CS-404 | Deploy-event ingestion | /v1/events/deploy; minutes_since_code_change; unsigned artifact -> deny. | Binance-pattern fixture escalates/denies. | 4d | CS-104 | FR-PRV-4 |
| CS-405 | HA mode | Active/passive with shared store; fail-closed failover. | Chaos test: failover with no cap violations. | 8d | CS-306 | NFR-3 |
| CS-406 | Passkey approvals | WebAuthn approvals bound to payload_hash. | Approve via passkey e2e. | 4d | CS-203 |  |
| CS-407 | Solana support | Decoder + signer adapter for Solana. | Seed Solana attacks blocked. | 8d | CS-141 |  |
| CS-408 | External security audit | Independent audit of core + guard. | Report published; criticals fixed. | 15d | CS-401,CS-403 |  |
