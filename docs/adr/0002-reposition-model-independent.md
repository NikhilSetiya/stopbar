# ADR 0002: Lead with model-independent controls; prompt-injection is one input among several

- Status: **Accepted (go)**
- Date: 2026-11-08
- Task: CS-513 (research track close-out)
- Evidence: [`docs/research/pilots-1-2.md`](../research/pilots-1-2.md); pilot artifacts under `research/agentdojo/results/` and `research/walletagent/results/`

## Context

Two pre-registered research pilots evaluated Stopbar's taint/policy enforcement
against prompt injection.

- **Pilot 1** (AgentDojo banking, Claude Haiku 4.5): attack success **0% on both
  the undefended (A0) and defended (A2) arms**. Session-level taint capped a
  *perfect* agent at a 56.2-point usefulness loss (9 of 16 tasks), all from the
  single `tainted-state-change` rule — the PRD kill-criterion signal for
  session-level taint.
- **Pilot 2** (real-incident wallet agent, DeepSeek-V4.1-Flash victim, Qwen3.5-9B
  attacker via PyRIT): competence passed (16/20); attack validity **0/25 on the
  undefended arm**, and uninterpretable — the attacker partly refused and
  delivery for three of four scenarios was unverified.

Neither stock automated attacker landed a single success *even without a defence*,
against either victim. The pilots also found and fixed real defects (no taint
wiring, missing WETH decoding, swap-recipient handling, EIP-7702, two harness
scoring bugs) and confirmed deterministic, model-independent blocking in the
corpus.

## Decision

1. **Reposition the headline** from "stops prompt injection" (T1) to the controls
   that hold **whatever the model does**: hard loss caps, independent intent
   decoding, allowlists, and a verifiable audit trail against **compromised
   requesters (T3, Binance)** and **agent mistakes (T2, OpenClaw)**.
2. **Prompt-injection defence becomes one input among several**, not the lead. No
   security claim about it is made from the pilots. The controls themselves are
   unchanged.
3. **Field-level taint stays in Phase 3** as the pre-registered comparison against
   the session-level rule pilot 1 showed to be too blunt. The research track is
   **closed**; it is not reopened to chase a stronger attacker (a public injection
   dataset would be a new pre-registered version, but the bottleneck is a
   deployable product, not more attack research).
4. **Always persist transcripts** in any future paid evaluation run (now done in
   `research/walletagent/harness/stages.py`), so a null result is diagnosable.

Updates `PRD.md` §1 (positioning) and §2.4 (pilot findings). HLD/LLD are
unchanged — this is a framing and roadmap decision, not an architecture change.

## Consequences

- The strongest, demonstrated claim ("holds whatever the model does") is the one
  already proven deterministically in `make e2e`, which is more credible than an
  unproven injection-defence claim.
- The product roadmap returns to the thin slice: CS-103 (auth), CS-131/132/133
  (real prices, balances, destination registry — retiring the dev stubs),
  CS-181/183 (SDK + production-ready agent adapter), then the Phase 2 launch.
- If field-level taint (Phase 3) is later measured and works, T1 can be promoted
  back with evidence; until then it stays demoted. This ADR is superseded only by
  a pilot that produces an interpretable T1 measurement.
