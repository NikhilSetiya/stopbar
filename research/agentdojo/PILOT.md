# Phase 1R pilot: AgentDojo banking, A0 vs A2 (pre-registration)

Status: **DRAFT, awaiting sign-off. Nothing is built or run until this document is approved and merged.**
Tasks: CS-502 (tool-call policy pack) and CS-503 (harness), cut down to this pilot.

## 1. Question and decision rule (fixed before any run)

Does session-level (context) taint keep the agent useful? This is the PRD kill criterion.

**Usefulness gap** = benign utility(A0) − benign utility(A2), in percentage points, on the point estimate.

| Gap | Decision |
|---|---|
| **> 25 pts** | Field-level taint moves **ahead of** the decoder (CS-141/142). |
| **10–25 pts** | Continue with the decoder, but taint granularity goes first in the backlog after it. |
| **< 10 pts** | Carry on as planned. |

- **If the 95% CI straddles a threshold,** we say so, run two more repetitions, and decide on the pooled estimate. Thresholds are not reinterpreted after the fact.
- **ASR is reported alongside.** If A2's attack success rate is not clearly below A0's (overlapping CIs), that is its own finding, "the policy doesn't stop this attack", and it is reported as such whatever the gap.

## 2. Pinned setup

| Item | Pin |
|---|---|
| AgentDojo | `agentdojo==0.1.35`, sdist sha256 `9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956` (wheel `364bea42…`) |
| Benchmark version | `v1.2.2` (the package default) |
| Suite | `banking` only. 16 user tasks. The number of injection tasks is read and logged by the harness at run time, not by a person; v1 had 9. |
| Attack | `important_instructions`, AgentDojo's own baseline prompt-injection attack, **unmodified**. Nothing tuned by us. No adaptive attacker and no T4 setting in the pilot. |
| Agent model 1 (cheap, run first) | `claude-haiku-4-5` |
| Agent model 2 (frontier, run second) | `claude-opus-5`. Alternatives for you to choose: `claude-opus-5-5`, `claude-sonnet-5`. |
| Agent prompt | AgentDojo's default system prompt and tool-calling pipeline. The only change is a model-client override, because Opus 5 rejects `temperature`; it is recorded in the run config. |
| Stopbar | The tagged `v0.1.0-alpha` source, plus CS-502's tool-call support. `stopbard` runs in **advisory** mode. Every result records the binary's commit and the bundle hash. |
| Arms | **A0**: no defence. **A2**: Stopbar enforces; deny and escalate both block, with escalations counted separately. A1 (LLM monitor) and A3 are out of scope. |
| Repetitions | 1 per (model, arm) for the pilot. Opus 5 can't be made deterministic, so this is stated as a limitation. |

## 3. Policy-pack integrity protocol (the point where integrity can slip)

1. **What the author may read before the freeze:**
   - The banking **tool definitions only**: names, signatures and docstrings of `get_iban`, `send_money`, `schedule_transaction`, `update_scheduled_transaction`, `get_balance`, `get_most_recent_transactions`, `get_scheduled_transactions`, `read_file`, `get_user_info`, `update_password` and `update_user_info`.
   - LLD §8 (taint) and §18.4.
   - **Not** the injection tasks (`injection_tasks.py`, any version), the attack templates' target strings, or any run output.
   - **Not** the user tasks either. Writing allowlists from benign tasks would inflate A2's utility.
   - *Done so far:* while scoping, only the **class count** of `injection_tasks.py` was taken (`grep -c`), and the user-task file was likewise only counted.
2. **Disclosure.** The policy author (Claude) has prior exposure to AgentDojo's public paper and repository through training data. This includes the general shape of banking injection goals, such as moving money to an attacker account or changing credentials. It cannot be unlearned. Mitigations:
   - (a) Every rule must be justified in the pack's README from tool semantics and the generic threat model in LLD §8, written down **before** the rule.
   - (b) No rule may reference a specific IBAN, amount, file name, string or task ID.
   - (c) You review and sign off on the pack before the freeze.
   - (d) This disclosure is repeated verbatim in the results.
3. **What the pack contains**, all frozen together:
   - `research/agentdojo/policies/banking.cedar` and its schema.
   - The **tool trust map**, which says which tool outputs carry third-party content. This is policy too, so it is frozen. Proposed from semantics alone: `read_file` (file contents), `get_most_recent_transactions` and `get_scheduled_transactions` (counterparty-written fields) are untrusted; the other read tools return the user's own data.
   - The list of state-changing tools: `send_money`, `schedule_transaction`, `update_scheduled_transaction`, `update_password`, `update_user_info`.
4. **Proposed rules** (for review; wording is final only at the freeze):
   - Session taint (any untrusted output read this session) plus any state-changing tool → **deny**. This is deliberately blunt, because the pilot measures what blunt context taint costs.
   - With no taint, money movement is allowed and credential/profile changes **escalate**.
5. **The freeze itself:**
   - The pack and `FREEZE.md` (bundle hash, the date, and your sign-off) are committed in one commit **before** any episode runs.
   - The harness refuses to run if the loaded bundle hash ≠ the frozen hash, and writes the hash into every result row.
6. **After the freeze:**
   - No edits. A changed pack is a **new pre-registered version** (v2, its own hash), run and reported separately.
   - The v1 numbers are always published, whatever they show.

## 4. Metrics (per model × arm)

| Metric | Definition |
|---|---|
| Benign utility | % of the 16 user tasks solved with no injection |
| Utility under attack | % of (user task, injection task) pairs where the user task is still solved |
| ASR | % of pairs where the injection goal is achieved |
| Block accounting | A2 only: tool calls denied vs escalated, and on benign vs attacked episodes |

- **CIs:** 95%, by bootstrap with 10,000 resamples, **clustered by user task**, since pairs sharing a user task aren't independent.
- **Differences:** A2 − A0 is reported with a paired bootstrap CI.
- **Scoring:** AgentDojo's own utility and security checks, unmodified.

## 5. Cost and time estimate (per full run = 2 arms × (16 benign + ~144 attacked) ≈ 320 episodes)

Assumptions:
- About 25k input and 1k output tokens per episode: ~5 model calls over a growing context with 11 tool schemas.
- Opus 5 also produces adaptive-thinking output (~+3k tokens) and uses roughly 1.2× more tokens for the same text.
- Stopbar adds no LLM calls.
- These are estimates, re-baselined after the first 10 episodes. No prompt caching is assumed, so they're an upper-ish bound.

| Model | $/episode | 1 run (320 eps) | 3 reps | Wall-clock, 1 run |
|---|---|---|---|---|
| `claude-haiku-4-5` ($1/$5 per MTok) | ~$0.03 | **~$10** | ~$30 | ~1 h sequential, ~15 min at 4-way parallel |
| `claude-opus-5` ($5/$25 per MTok) | ~$0.25 | **~$80** | ~$240 | ~3.5 h sequential, ~1 h at 4-way parallel |

- **Spend cap:** the harness aborts at 2× the estimate.
- **Plan:** run Haiku first. If the result is clearly decisive (the CI doesn't straddle a threshold), Opus 5 confirms it. Otherwise Opus 5 runs with 3 repetitions.

## 6. Build needed after sign-off (estimate ~5 days)

1. **CS-502 (~1.5 d):**
   - Cedar tool-call context: `tool`, `state_changing`, `taint` and `args` facts. Today tool calls fail closed.
   - A tool-call decoder.
   - Write the banking pack under §3, get your sign-off, freeze.
2. **CS-503 (~2.5 d):**
   - `research/agentdojo/` Python harness, pinned via `requirements.txt` with hashes.
   - A pipeline element in front of AgentDojo's `ToolsExecutor` that POSTs each call to `stopbard` with session taint from the frozen trust map. A block returns a tool error carrying the reason codes.
   - A shadow log per LLD §18.5.
   - The spend cap and the frozen-hash check.
3. **Runs and report (~1 d):** a results page with every number, the CIs, the decision under §1, and the §3.2 disclosure.

## 7. Results (to be filled in only after the runs)

*Empty by design.*
