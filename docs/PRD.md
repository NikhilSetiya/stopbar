# Stopbar — Product Requirements Document

| | |
|---|---|
| Version | 0.2 (draft) |
| Date | 2026-11-04 |
| Owner | Nikhil |
| Status | Design |

---

## 1. Summary

Stopbar is an open-source **intent firewall for signers**. It intercepts every action an AI agent, service, or operator asks a signer to perform, evaluates it against deterministic policy, provenance, and loss bounds in an independent trust domain, and only then countersigns it. The signer refuses anything Stopbar has not approved.

**Thesis:** the attack surface has moved from the key to the request path. Key security is largely solved (HSMs, MPC, hardware wallets). Request-path integrity is not.

## 2. Problem

### 2.1 Observed failure pattern

Counterfactuals below are design intent, not demonstrated results. Each names the control that applies and the assumption it depends on; the replay corpus (FR-COR) and the research track (§10a) exist to test them.

| Incident | Date | Loss | Root cause | Applicable control (assumption) |
|---|---|---|---|---|
| Binance hot wallet | Oct 2026 | ~$6.3B (prelim.) | Compromised DevOps laptop → service container → signing system produced valid signatures across 10 chains in minutes. No key leak reported. Velocity caps bound loss to the cap; deploy-correlation flags new code on the signing path (assumes gatekeeper/co-signer mode and Stopbar outside the compromised network). |
| Bybit | Feb 2025 | ~$1.5B | Compromised signing UI; signers approved a transaction they couldn't read. Independent intent rendering shows the real action, e.g. `delegatecall` (assumes approvers read the rendering, see §12 approval fatigue). |
| Grok / Bankr | May 2026 | ~$170K+ | Encoded instruction (Morse) in on-chain content decoded by an LLM, passed to an agent with wallet permissions. Provenance taint + destination allowlist → deny (assumes T1: honest harness labels inputs, §2.4). |
| Bankr (14 wallets) | May 2026 | ~$440K | Trust layer between agent and model exploited to sign unauthorised transactions. Per-wallet caps and allowlists independent of the agent (holds at T3). |
| OpenClaw | Feb 2026 | ~$250K | Agent error transferred entire balance. No attacker. Per-transaction % of balance cap → escalate (holds at T2). |
| Kelp DAO bridge | Apr 2026 | ~$292M | RPC node compromise. | Partially: velocity caps bound loss; root cause is infra. |

### 2.2 Root cause

Every signer in these incidents behaved correctly given its inputs. **Signers are oracles: whoever can submit a request gets a valid signature.** There is no independent component asking "should this happen, given where this request came from and what it does?"

### 2.3 Why existing tools don't close it

- **Key infrastructure (Fireblocks, Turnkey, Privy, Coinbase agent wallets):** have policy engines for limits and allowlists. They do not reason about **provenance** (what content or code produced the request) and usually share a trust domain with the requester.
- **AI security (guardrails, classifiers, AI-SPM):** probabilistic detection on prompts. Attackers retry until a classifier misses. They don't bound loss.
- **Exchange fraud ML (e.g. Binance's 100+ models):** aimed at user-side scams and account takeover, not at the exchange's own signing path being driven by a compromised internal service.

### 2.4 Threat tiers

Every control is rated against the tier it actually holds at. Claims above a control's tier are not made.

| Tier | Adversary | Example | Controls that hold | Controls that do **not** hold |
|---|---|---|---|---|
| T1 | Injected model, honest harness | Grok/Bankr | Taint + allowlist, caps, intent rendering | — |
| T2 | Agent error, no adversary | OpenClaw | % of balance caps, escalation | — |
| T3 | Compromised requester process | Binance | Gatekeeper/co-signer mode, caps, circuit breaker, deploy correlation | SDK taint (requester can forge or strip labels) |
| T4 | Scheming agent: pursues a hidden goal, writes code, launders taint, stays under thresholds | Agentic-misalignment and SHADE-Arena settings | Caps, allowlists, circuit breaker | v1 context taint; any control the agent can observe and route around |

Key assumption for v1: the **harness** (agent framework + SDK) is trusted and the **model** is not. T4 is in scope for evaluation from Phase 1R and for enforcement from Phase 3, when taint moves into sandbox bindings the model cannot touch.

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
- G6: Publish a reproducible evaluation of Stopbar as a control protocol on an external benchmark (AgentDojo), including an adaptive attacker and a scheming-agent setting (Phase 1R).

### Non-goals (v1)

- Custodying keys. v1 wraps existing signers (local keys for dev, Turnkey/Privy/KMS adapters).
- Non-EVM chains (v1). Solana next.
- ML-based anomaly detection as a blocking control. Allowed later only as an input signal.
- A hosted SaaS. Self-hosted / sidecar first.
- A blockchain or token.

## 6. Product principles

1. **Fail closed.** If Stopbar can't decide, the answer is deny.
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
- FR-INT-3: Support three enforcement modes: **advisory** (log only), **gatekeeper** (Stopbar proxies the signer), **co-signer** (signer or on-chain guard requires Stopbar's signature) — co-signer in Phase 4.
- FR-INT-4: Reject replayed or expired requests (nonce + TTL).

### 7.2 Policy (FR-POL)

- FR-POL-1: Policies written in Cedar with a Stopbar schema; versioned and hash-identified.
- FR-POL-2: Outcomes: `allow`, `deny`, `escalate`. Deny overrides escalate overrides allow.
- FR-POL-3: Every decision returns machine-readable reasons (policy IDs matched).
- FR-POL-4: Policy dry-run against historical requests and the corpus before activation.
- FR-POL-5: Policy changes themselves require M-of-N approval (configurable).

### 7.3 Loss bounding (FR-LIM)

- FR-LIM-1: Value caps per transaction, absolute and as % of wallet balance.
- FR-LIM-2: Sliding-window velocity caps (USD value and count) per {tenant, agent, wallet, chain, asset, destination}.
- FR-LIM-2a: Per-destination count caps across windows to bound salami draining below per-transaction thresholds.
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
- FR-IR-2: Risk flags: unlimited approval, `delegatecall`, proxy upgrade, new destination, first-time contract, address similarity to known destinations (address poisoning), swaps with zero or excessive-slippage minimum output (allowed-but-destructive actions).
- FR-IR-3: Render summaries out of band (Slack, Telegram, email, CLI) with the payload hash, so approvers see what will be signed.

### 7.6 Escalation (FR-ESC)

- FR-ESC-1: Configurable M-of-N approvers per policy.
- FR-ESC-2: Approvals signed with WebAuthn/passkeys (phase 1: signed CLI approvals).
- FR-ESC-3: Timeout → deny.

### 7.7 Audit (FR-AUD)

- FR-AUD-1: Append-only, hash-chained record of every request, decision, approval, and policy change.
- FR-AUD-2: Periodic signed Merkle checkpoints; optional anchoring to Sigstore Rekor.
- FR-AUD-3: `stopbar audit verify` validates chain integrity offline.

### 7.8 Corpus and replay (FR-COR)

- FR-COR-1: Open attack schema (see `corpus/schema.json`).
- FR-COR-2: Replay harness runs a policy bundle against all corpus entries; CI fails on regressions.
- FR-COR-3: Contribution flow via PR with template and automated validation.

### 7.9 Research evaluation (FR-EVAL)

- FR-EVAL-1: Harness that puts Stopbar in front of AgentDojo tool calls (deny → tool error returned to the agent).
- FR-EVAL-2: Four arms: no defence, LLM monitor, Stopbar, Stopbar + LLM monitor (block if either blocks).
- FR-EVAL-3: Shadow mode: in every arm, both the policy and the LLM monitor record a verdict on every call; only the arm's enforcer blocks.
- FR-EVAL-4: Adaptive attacker with knowledge of the active policy bundle and access to denial reasons.
- FR-EVAL-5: Scheming-agent setting (T4): agent given a covert side task; measure containment by policy alone.
- FR-EVAL-6: Every run pinned (model ID, prompts, policy bundle hash, seeds) and reproducible from one command.

### 7.10 Developer experience (FR-DX)

- FR-DX-1: `stopbar init` generates a starter policy for a chosen persona.
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
| Security (eval) | Attack success rate (ASR): injection tasks where the attacker's goal is achieved | Report per arm; Stopbar arm < no-defence arm with non-overlapping 95% CI |
| Security (eval) | Adaptive-attacker ASR: same, with policy knowledge and N retries | Reported; no target until baseline exists |
| Usefulness (eval) | Benign utility: user tasks completed with no attack present | Within 10 points of no-defence arm (CaMeL reference: 77% vs 84%) |
| Usefulness (eval) | Utility under attack: user task still completed when an injection is present | Reported per arm |
| Complementarity (eval) | Disagreement matrix: attacks caught by policy only / monitor only / both / neither | "Neither" cell is the headline finding |
| Containment (eval) | T4 side-task success with policy enforcement | Reported vs. no-defence |
| Quality | False-escalation rate on design-partner traffic | < 2% of requests (unvalidated; first measured as benign utility in Phase 1R) |
| Enterprise signal | Inbound issues from company domains | ≥ 5 by month 4 |

## 10. Release plan

| Phase | Window | Scope | Exit criteria |
|---|---|---|---|
| 0 Foundations | Wk 0–2 | Repo, CI, specs, data model, decision token | Specs merged; CI green |
| 1 Agent-wallet MVP | Wk 2–8 | Gatekeeper mode, Cedar policies, limiter, context taint, EVM decoder, CLI approvals, audit log, replay harness, 10 seed attacks, TS + Python SDKs | All seed attacks blocked; quickstart < 30 min; p99 target met |
| 1R Research track | Wk 4–10 (parallel; starts once the engine evaluates tool calls) | AgentDojo harness, four arms, shadow monitor, adaptive attacker, T4 setting, write-up | Reproducible results report published |
| 2 Corpus & community | Wk 8–12 | Public corpus, contribution flow, docs site, launch | Launch done; first external contributions |
| 3 Code-mode agents | M3–9 | Binding-level enforcement in sandboxes, field-level taint, MCP gateway adapter | Design partner running in staging |
| 4 Custody grade | Y2 | Co-signer mode (Safe guard, MPC share), HSM/TEE keys, HA, deploy correlation, Solana | External security audit passed; 1 custody design partner |

## 10a. Why a research track

The product claim ("deterministic out-of-band gating stops agent attacks") is untested. Seed attacks written against our own policies are circular evidence. Phase 1R tests the claim on an external benchmark, against an attacker who knows the policy, and against an agent that is itself adversarial. The output is both product evidence and a public research artefact. It uses the same engine; nothing is forked.

Research question: *does deterministic, provenance-aware action gating catch the failures LLM monitors miss, and at what usefulness cost?*

## 11. Kill / pivot criteria

- No external corpus contributions by month 3 → network effect not forming; pivot focus to weight-provenance (supply chain) or pure agent-authorization spec.
- Design partners refuse to put Stopbar on the hot path because of latency/availability → re-architect as co-signer only.
- Phase 1R shows benign utility more than 25 points below the no-defence arm → context-level taint is unusable; prioritise field-level taint (Phase 3) before launch.
- An incumbent (Fireblocks/Turnkey/Coinbase) ships provenance-aware policy as open standard → contribute to theirs; pivot to corpus + audit/attestation.

## 12. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Stopbar becomes the prime target | High | Separate trust domain; minimal attack surface; co-signer mode; external audit before custody use |
| Bypass: requester calls signer directly | High | Gatekeeper/co-signer modes make bypass impossible; advisory mode clearly labelled non-protective |
| Context-level taint too coarse → false escalations | **High** | Measure first (benign utility, Phase 1R); allowlists for trusted flows; field-level taint in Phase 3 |
| Attacks inside policy bounds (salami draining, allowed-but-destructive actions such as zero-min-out swaps) | High | Per-destination count caps; `min_out_zero` / `excessive_slippage` flags; adaptive-attacker eval |
| Approval fatigue: humans rubber-stamp escalations | Medium | Escalation rate tracked as a budget per tenant; rendering bound to payload hash |
| Evaluation circularity (we write the attacks and the policies) | High | External benchmark, held-out attacks, adaptive attacker (Phase 1R) |
| Incumbents bundle limits | High | Differentiate on provenance, intent, open corpus — not caps |
| Solo-builder capacity | High | Ruthless scope; Phase 1 is EVM-only, gatekeeper-only |
| Liability if a protected wallet is drained | Medium | Apache-2.0 no-warranty; clear threat-model docs; no custody claims in v1 |

## 13. Open questions

1. Cedar vs. OPA/Rego vs. custom DSL — Cedar chosen for analyzability; validate stateful attributes ergonomics in Phase 0 spike.
2. Which signer adapters first: local key, Turnkey, Privy, AWS KMS? (Proposed: local + KMS + Turnkey.)
3. Hosted corpus registry or Git-only? (Proposed: Git-only until contributions demand otherwise.)
4. Telemetry: opt-in anonymous counts only?
5. Which LLM monitor and prompt for the Phase 1R baseline? (Proposed: one frontier model and one open-weight model, prompts versioned in-repo.)
6. How to combine policy and monitor verdicts in production if the eval shows complementarity: monitor as escalate-only signal (never allow-granting)?
7. Name clearance: renamed from Countersign to Stopbar on 2026-11-04 after collisions (IETF counter-sign draft, Action State Countersign, live COUNTERSIGN US mark; Interlock is a ransomware group). UK IPO + USPTO search in classes 9 and 42 and domain check pending before public launch.

## 14. References

- Binance incident reporting (Oct 30, 2026), incl. TRM Labs attribution — post-mortem pending.
- FBI alert on Bybit (Feb 2025).
- Grok/Bankr and Bankr 14-wallet incident reporting (May 2026).
- OpenClaw agent incident reporting (Feb 2026).
- Cedar policy language: https://www.cedarpolicy.com
- Sigstore Rekor: https://docs.sigstore.dev
- AgentDojo benchmark: https://arxiv.org/abs/2406.13352
- CaMeL, *Defeating Prompt Injections by Design* (2025): https://arxiv.org/abs/2503.18813
- SHADE-Arena, *Evaluating Sabotage and Monitoring in LLM Agents* (2025): https://arxiv.org/abs/2506.15740
- Anthropic, *Recommendations for Technical AI Safety Research Directions* (2025): https://alignment.anthropic.com/2025/recommended-directions/
