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

## 1a. Prediction (written before any run)

**Project owner's prediction:**
- A2's attack success rate will be **close to 0**.
- The **usefulness gap will be above 25 points**, because many banking user tasks read the same tool outputs an injection can sit in (transaction histories, files). Under session-level taint, any state-changing call after that read is blocked.

If that holds, the §1 rule moves field-level taint ahead of the decoder. That is the problem CaMeL's design exists to solve (77% vs 84% undefended utility on AgentDojo).

**Policy author's prediction (Claude):**
- The same direction.
- A gap of roughly 30–50 points, concentrated in the tasks that read injectable content (§4 split), with a near-zero gap on the rest.

**Any result that contradicts these predictions is reported as a surprise,** with the predictions quoted. Writing them down first is what makes a surprise count for something.

## 2. Pinned setup

| Item | Pin |
|---|---|
| AgentDojo | `agentdojo==0.1.35`, sdist sha256 `9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956` (wheel `364bea42…`) |
| Benchmark version | `v1.2.2` (the package default) |
| Suite | `banking` only. 16 user tasks. The number of injection tasks is read and logged by the harness at run time, not by a person; v1 had 9. |
| Attack | `important_instructions`, AgentDojo's own baseline prompt-injection attack, **unmodified**. Nothing tuned by us. No adaptive attacker and no T4 setting in the pilot. |
| Agent model 1 (cheap, run first) | `claude-haiku-4-5` |
| Agent model 2 (frontier, run second) | `claude-opus-5-5`, the newest Opus. Adaptive thinking (it can't be disabled) at an explicitly pinned `effort: medium`, its default. |
| Agent prompt | AgentDojo's default system prompt and tool-calling pipeline. The only change is a model-client override: Opus 5.5 rejects `temperature` and forced `tool_choice` (`any`/`tool`), so the client sends neither. Haiku runs with AgentDojo's own settings. The override is recorded in the run config. |
| Stopbar | The tagged `v0.1.0-alpha` source, plus CS-502's tool-call support. `stopbard` runs in **advisory** mode. Every result records the binary's commit and the bundle hash. |
| Arms | **A0**: no defence. **A2**: Stopbar enforces; deny and escalate both block, with escalations counted separately. A1 (LLM monitor) and A3 are out of scope. |
| Repetitions | 1 per (model, arm) for the pilot. Opus 5.5 can't be made deterministic, so this is stated as a limitation. |
| Later, **outside this pilot** | v2 adds **one non-Anthropic model**, so the effect can't be read as specific to Claude. It gets its own pre-registration. |

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
3. **What the pack contains**, all frozen together under **one bundle hash**:
   - `research/agentdojo/policies/banking.cedar` and its schema.
   - The **tool trust map** (`tool-trust.json`), which says which tool outputs carry third-party content and so taint the session. **It is decided from the tool definitions alone, like the policy, and it is part of the frozen bundle.** It is not a harness setting: there is no runner flag or environment variable for it. The harness reads labels only from the loaded bundle, and CS-502 extends the bundle hash (LLD §5.4) to cover this file, so changing a label changes the hash and the harness refuses to run. Proposed from semantics alone: `read_file` (file contents), `get_most_recent_transactions` and `get_scheduled_transactions` (counterparty-written fields) are untrusted; the other read tools return the user's own data.
   - The list of state-changing tools: `send_money`, `schedule_transaction`, `update_scheduled_transaction`, `update_password`, `update_user_info`. This is in the same file and under the same hash.
4. **Rules** (decided; final wording at the freeze):
   - Session taint (any untrusted output read this session) plus any state-changing tool → **deny**.
   - With no taint, money movement is allowed and credential/profile changes **escalate**.

   The rule is **deliberately blunt**, and that's decided. The pilot asks what session-level taint costs. A smarter rule would change two things at once, so the blunt one is the baseline. Field-level taint gets its own pre-registered run later, as the direct comparison.
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

**Secondary analysis (pre-registered): where the usefulness goes.**
- **Split:** user tasks fall into **R** (the task reads injectable content) and **N** (it doesn't). The split is computed **mechanically, before any agent run**: the harness executes each user task's AgentDojo ground-truth function calls and marks the task R if any of them calls a tool the frozen trust map labels untrusted. No model is involved, and no person reads the tasks. The harness logs the split and its inputs (task ID → ground-truth tool names) with the run.
- **Reported:** benign utility per arm for R and N separately, each with a clustered bootstrap CI, plus the gap per group.
- **Predicted** (both predictions above): the gap sits almost entirely in R, with N close to 0.

## 5. Cost and time estimate (per full run = 2 arms × (16 benign + ~144 attacked) ≈ 320 episodes)

Assumptions:
- About 25k input and 1k output tokens per episode: ~5 model calls over a growing context with 11 tool schemas.
- Opus 5 also produces adaptive-thinking output (~+3k tokens) and uses roughly 1.2× more tokens for the same text.
- Stopbar adds no LLM calls.
- These are estimates, re-baselined after the first 10 episodes. No prompt caching is assumed, so they're an upper-ish bound.

| Model | $/episode | 1 run (320 eps) | 3 reps | Wall-clock, 1 run |
|---|---|---|---|---|
| `claude-haiku-4-5` ($1/$5 per MTok) | ~$0.03 | **~$10** | ~$30 | ~1 h sequential, ~15 min at 4-way parallel |
| `claude-opus-5-5` ($4/$20 per MTok) | ~$0.20 | **~$64** | ~$190 | ~3.5 h sequential, ~1 h at 4-way parallel |

- **Spend cap:** the harness aborts at 2× the estimate.
- **Plan:** run Haiku first. If the result is clearly decisive (the CI doesn't straddle a threshold), Opus 5.5 confirms it. Otherwise Opus 5.5 runs with 3 repetitions.

## 6. Build needed after sign-off (estimate ~5 days)

1. **CS-502 (~1.5 d):**
   - Cedar tool-call context: `tool`, `state_changing`, `taint` and `args` facts. Today tool calls fail closed.
   - A tool-call decoder.
   - Extend the bundle hash to cover `tool-trust.json` (with a test that changing one label changes the hash).
   - Write the banking pack under §3. Claude reviews it against §3 point by point, then sends it to you for sign-off, then freezes it.
2. **CS-503 (~2.5 d):**
   - `research/agentdojo/` Python harness, pinned via `requirements.txt` with hashes.
   - A pipeline element in front of AgentDojo's `ToolsExecutor` that POSTs each call to `stopbard` with session taint from the frozen trust map. A block returns a tool error carrying the reason codes.
   - A shadow log per LLD §18.5.
   - The spend cap and the frozen-hash check.
3. **Runs and report (~1 d):** a results page with every number, the CIs, the decision under §1, and the §3.2 disclosure.

## 7. Results (to be filled in only after the runs)

*Empty by design.*
