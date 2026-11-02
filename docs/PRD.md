# Countersign — Product Requirements Document

| | |
|---|---|
| Version | 0.1 (draft) |
| Date | 2026-11-02 |
| Owner | Nikhil |
| Status | Design |

---

## 1. Summary

Countersign is an open-source **intent firewall for signers**. It intercepts every action an AI agent, service, or operator asks a signer to perform, evaluates it against deterministic policy, provenance, and loss bounds in an independent trust domain, and only then countersigns it. The signer refuses anything Countersign has not approved.

**Thesis:** the attack surface has moved from the key to the request path. Key security is largely solved (HSMs, MPC, hardware wallets). Request-path integrity is not.

## 2. Problem

### 2.1 Observed failure pattern

| Incident | Date | Loss | Root cause | Would Countersign have helped? |
|---|---|---|---|---|
| Binance hot wallet | Oct 2026 | ~$6.3B (prelim.) | Compromised DevOps laptop → service container → signing system produced valid signatures across 10 chains in minutes. No key leak reported. | Yes: velocity caps bound loss to the cap; deploy-correlation flags code installed on the signing path hours before; separate trust domain not reachable from the container. |
| Bybit | Feb 2025 | ~$1.5B | Compromised signing UI; signers approved a transaction they couldn't read. | Yes: independent intent rendering on a separate channel shows the real action (e.g. `delegatecall` changing wallet logic). |
| Grok / Bankr | May 2026 | ~$170K+ | Encoded instruction (Morse) in on-chain content decoded by an LLM, passed to an agent with wallet permissions. | Yes: provenance taint (`untrusted_onchain`, `decoded`) on the request + destination not allowlisted → deny. |
| Bankr (14 wallets) | May 2026 | ~$440K | Trust layer between agent and model exploited to sign unauthorised transactions. | Yes: per-wallet caps and allowlists independent of the agent. |
| OpenClaw | Feb 2026 | ~$250K | Agent error transferred entire balance. No attacker. | Yes: per-transaction % of balance cap → escalate. |
| Kelp DAO bridge | Apr 2026 | ~$292M | RPC node compromise. | Partially: velocity caps bound loss; root cause is infra. |

### 2.2 Root cause

Every signer in these incidents behaved correctly given its inputs. **Signers are oracles: whoever can submit a request gets a valid signature.** There is no independent component asking "should this happen, given where this request came from and what it does?"

### 2.3 Why existing tools don't close it

- **Key infrastructure (Fireblocks, Turnkey, Privy, Coinbase agent wallets):** have policy engines for limits and allowlists. They do not reason about **provenance** (what content or code produced the request) and usually share a trust domain with the requester.
- **AI security (guardrails, classifiers, AI-SPM):** probabilistic detection on prompts. Attackers retry until a classifier misses. They don't bound loss.
- **Exchange fraud ML (e.g. Binance's 100+ models):** aimed at user-side scams and account takeover, not at the exchange's own signing path being driven by a compromised internal service.

## 3. Why now

- Agents are being handed wallets and API authority at scale (x402, ERC-8004 agent identity, agent kits from wallet providers).
- Code-mode agents (scripts calling tools in sandboxes) remove per-call approval points.
- Attack cost has collapsed: AI makes exploit generation and social engineering cheap and fast.
- The most popular open red-teaming tool (Promptfoo) is now owned by a closed lab — a neutral open standard is missing.

## 4. Users and jobs to be done

| Persona | Context | Job | Phase |
|---|---|---|---|
| **P1 Agent developer** | Builds agents that hold hot wallets (trading, payments, DeFi automation) | "Let my agent transact without it being able to drain the wallet when tricked or wrong." | 1 |
| **P2 Platform / security engineer** | Runs enterprise agents incl. code-mode with tool bindings | "Enforce what agents may do per call, even inside generated code, and prove it afterwards." | 3 |
| **P3 Custody / exchange security lead** | Operates hot wallets and signing services | "Make a compromised internal service unable to produce a catastrophic withdrawal." | 4 |
| **P4 Security researcher** | Finds agent / wallet attacks | "Contribute an attack once; see it blocked everywhere." | 2 |

## 5. Goals and non-goals

### Goals (v1)

- G1: Block every attack in the seed corpus for EVM agent wallets via deterministic policy.
- G2: Add < 25 ms p99 latency to the allow path (excluding human escalation).
- G3: Integrate into an existing agent in < 30 minutes (SDK + 1 policy file).
- G4: Produce a verifiable audit trail for every decision.
- G5: Establish the open policy + corpus formats as the default others adopt.

### Non-goals (v1)

- Custodying keys. v1 wraps existing signers (local keys for dev, Turnkey/Privy/KMS adapters).
- Non-EVM chains (v1). Solana next.
- ML-based anomaly detection as a blocking control. Allowed later only as an input signal.
- A hosted SaaS. Self-hosted / sidecar first.
- A blockchain or token.

## 6. Product principles

1. **Fail closed.** If Countersign can't decide, the answer is deny.
2. **Separate trust domain.** The checker must not be compromisable by compromising the requester.
3. **Bound before detect.** Deterministic loss caps beat probabilistic detection.
4. **Deterministic first.** Same input + same policy version = same decision, always. Replayable.
5. **Readable intent.** No human approves anything they can't read in plain language.
6. **Open formats.** Policy language, decision token, and corpus schema are open specs.

## 7. Functional requirements

IDs are referenced from the [task backlog](TASKS.md).

### 7.1 Interception (FR-INT)

- FR-INT-1: Accept action requests via HTTP API and in-process SDK (TypeScript, Python).
- FR-INT-2: Normalise requests into a canonical `ActionRequest` (see LLD §3).
- FR-INT-3: Support three enforcement modes: **advisory** (log only), **gatekeeper** (Countersign proxies the signer), **co-signer** (signer or on-chain guard requires Countersign's signature) — co-signer in Phase 4.
- FR-INT-4: Reject replayed or expired requests (nonce + TTL).

### 7.2 Policy (FR-POL)

- FR-POL-1: Policies written in Cedar with a Countersign schema; versioned and hash-identified.
- FR-POL-2: Outcomes: `allow`, `deny`, `escalate`. Deny overrides escalate overrides allow.
- FR-POL-3: Every decision returns machine-readable reasons (policy IDs matched).
- FR-POL-4: Policy dry-run against historical requests and the corpus before activation.
- FR-POL-5: Policy changes themselves require M-of-N approval (configurable).

### 7.3 Loss bounding (FR-LIM)

- FR-LIM-1: Value caps per transaction, absolute and as % of wallet balance.
- FR-LIM-2: Sliding-window velocity caps (USD value and count) per {tenant, agent, wallet, chain, asset, destination}.
- FR-LIM-3: Tenant-wide circuit breaker: halt all signing when aggregate outflow exceeds threshold.
- FR-LIM-4: Reserve-then-commit accounting so concurrent requests can't race past caps.
- FR-LIM-5: Price oracle with staleness bound; stale price → escalate.

### 7.4 Provenance (FR-PRV)

- FR-PRV-1: SDK labels inputs entering agent context (`trusted_user`, `untrusted_web`, `untrusted_onchain`, `untrusted_email`, `tool_output`, `decoded`).
- FR-PRV-2: v1 context-level taint: any action produced while tainted content was in context carries those labels.
- FR-PRV-3: Workload identity on requests (SPIFFE ID or signed service identity).
- FR-PRV-4: Ingest deploy/change events; expose `minutes_since_code_change` for the requesting workload (Phase 4, designed in v1).
- FR-PRV-5 (Phase 3): field-level taint via instrumented code-mode bindings.

### 7.5 Intent rendering (FR-IR)

- FR-IR-1: Decode EVM transactions (native transfer, ERC-20 transfer/approve, ERC-721/1155, Safe txs, multicall) into an `IntentSummary`.
- FR-IR-2: Risk flags: unlimited approval, `delegatecall`, proxy upgrade, new destination, first-time contract, address similarity to known destinations (address poisoning).
- FR-IR-3: Render summaries out of band (Slack, Telegram, email, CLI) with the payload hash, so approvers see what will be signed.

### 7.6 Escalation (FR-ESC)

- FR-ESC-1: Configurable M-of-N approvers per policy.
- FR-ESC-2: Approvals signed with WebAuthn/passkeys (phase 1: signed CLI approvals).
- FR-ESC-3: Timeout → deny.

### 7.7 Audit (FR-AUD)

- FR-AUD-1: Append-only, hash-chained record of every request, decision, approval, and policy change.
- FR-AUD-2: Periodic signed Merkle checkpoints; optional anchoring to Sigstore Rekor.
- FR-AUD-3: `countersign audit verify` validates chain integrity offline.

### 7.8 Corpus and replay (FR-COR)

- FR-COR-1: Open attack schema (see `corpus/schema.json`).
- FR-COR-2: Replay harness runs a policy bundle against all corpus entries; CI fails on regressions.
- FR-COR-3: Contribution flow via PR with template and automated validation.

### 7.9 Developer experience (FR-DX)

- FR-DX-1: `countersign init` generates a starter policy for a chosen persona.
- FR-DX-2: Docker image and single-binary sidecar.
- FR-DX-3: Quickstart: agent wallet protected in < 30 minutes.

## 8. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Allow-path latency added | p99 < 25 ms (sidecar), < 50 ms (networked) |
| NFR-2 | Throughput (single node) | ≥ 1,000 evaluations/sec |
| NFR-3 | Availability | Fail closed; HA mode in Phase 4 |
| NFR-4 | Determinism | 100% replay equality per policy version |
| NFR-5 | Security | Decision keys in KMS/HSM/TEE (Phase 4); no plaintext secrets in config |
| NFR-6 | Observability | OpenTelemetry traces + Prometheus metrics |
| NFR-7 | Supply chain | Signed releases (Sigstore), SBOM, pinned dependencies |

## 9. Success metrics

| Type | Metric | Target |
|---|---|---|
| North star | Attacks blocked in replay / attacks in corpus | 100% of applicable seed attacks by MVP |
| Adoption | Weekly active installs (opt-in telemetry) | 50 by week 12 |
| Network effect | External corpus contributions | ≥ 10 by month 3 (**kill/pivot signal**) |
| Quality | False-escalation rate on design-partner traffic | < 2% of requests |
| Enterprise signal | Inbound issues from company domains | ≥ 5 by month 4 |

## 10. Release plan

| Phase | Window | Scope | Exit criteria |
|---|---|---|---|
| 0 Foundations | Wk 0–2 | Repo, CI, specs, data model, decision token | Specs merged; CI green |
| 1 Agent-wallet MVP | Wk 2–8 | Gatekeeper mode, Cedar policies, limiter, context taint, EVM decoder, CLI approvals, audit log, replay harness, 10 seed attacks, TS + Python SDKs | All seed attacks blocked; quickstart < 30 min; p99 target met |
| 2 Corpus & community | Wk 8–12 | Public corpus, contribution flow, docs site, launch | Launch done; first external contributions |
| 3 Code-mode agents | M3–9 | Binding-level enforcement in sandboxes, field-level taint, MCP gateway adapter | Design partner running in staging |
| 4 Custody grade | Y2 | Co-signer mode (Safe guard, MPC share), HSM/TEE keys, HA, deploy correlation, Solana | External security audit passed; 1 custody design partner |

## 11. Kill / pivot criteria

- No external corpus contributions by month 3 → network effect not forming; pivot focus to weight-provenance (supply chain) or pure agent-authorization spec.
- Design partners refuse to put Countersign on the hot path because of latency/availability → re-architect as co-signer only.
- An incumbent (Fireblocks/Turnkey/Coinbase) ships provenance-aware policy as open standard → contribute to theirs; pivot to corpus + audit/attestation.

## 12. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Countersign becomes the prime target | High | Separate trust domain; minimal attack surface; co-signer mode; external audit before custody use |
| Bypass: requester calls signer directly | High | Gatekeeper/co-signer modes make bypass impossible; advisory mode clearly labelled non-protective |
| Context-level taint too coarse → false escalations | Medium | Allowlists for trusted flows; field-level taint in Phase 3 |
| Incumbents bundle limits | High | Differentiate on provenance, intent, open corpus — not caps |
| Solo-builder capacity | High | Ruthless scope; Phase 1 is EVM-only, gatekeeper-only |
| Liability if a protected wallet is drained | Medium | Apache-2.0 no-warranty; clear threat-model docs; no custody claims in v1 |

## 13. Open questions

1. Cedar vs. OPA/Rego vs. custom DSL — Cedar chosen for analyzability; validate stateful attributes ergonomics in Phase 0 spike.
2. Which signer adapters first: local key, Turnkey, Privy, AWS KMS? (Proposed: local + KMS + Turnkey.)
3. Hosted corpus registry or Git-only? (Proposed: Git-only until contributions demand otherwise.)
4. Telemetry: opt-in anonymous counts only?

## 14. References

- Binance incident reporting (Oct 30, 2026), incl. TRM Labs attribution — post-mortem pending.
- FBI alert on Bybit (Feb 2025).
- Grok/Bankr and Bankr 14-wallet incident reporting (May 2026).
- OpenClaw agent incident reporting (Feb 2026).
- Cedar policy language: https://www.cedarpolicy.com
- Sigstore Rekor: https://docs.sigstore.dev
