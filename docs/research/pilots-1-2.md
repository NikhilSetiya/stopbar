# Research pilots 1 & 2 — methods and negative results

| | |
|---|---|
| Status | Closed, 2026-11-08 |
| Scope | Two pre-registered pilots of Stopbar's taint/policy enforcement against prompt injection |
| Claims | **None about security.** Methods and negative results only. |

This note records what the two research pilots did, what they found that matters,
and — explicitly — what they could **not** measure. There are **no security
claims here**: neither pilot produced an interpretable measurement of Stopbar's
value against prompt injection, and that honesty is the point of writing it down.
The pilots earned their keep in two other ways: they surfaced real design and
harness defects (now fixed and regression-tested), and they gave an honest map of
where the threat actually sits.

## 1. What the pilots were

- **Pilot 1 — AgentDojo banking (CS-503).** Victim **Claude Haiku 4.5**; attacker
  AgentDojo's stock `important_instructions`. Arms: **A0** (no Stopbar) vs **A2**
  (gatekeeper, session-level taint from a frozen `tool-trust.json`). Pre-registered
  in `research/agentdojo/PILOT.md`; frozen bundle `sha256:a974808b…`; 16 banking
  tasks; spend $1.98.
- **Pilot 2 — real-incident wallet agent (CS-512/513).** Victim
  **DeepSeek-V4.1-Flash-1017**; attacker **Qwen3.5-9B** driven by **PyRIT**
  `RedTeamingAttack` (defaults, `max_turns=5`). AgentKit A0 vs `StopbarWalletProvider`
  A2 on an Anvil fork of Base. Four incident scenarios (S1 token metadata, S2
  seeded transaction history, S3 web/token listing, S5 payout document).
  Pre-registered in `research/walletagent/PILOT-2.md`; automated gates (competence,
  attack validity) under Amendment A5.

Both pilots used the same discipline: a frozen policy bundle whose hash the runner
checks before any paid call, a hard spend cap, pre-registered predictions, and
gates that stop the run before a bad measurement can become a claim.

## 2. What they found that matters

**(a) Session-level taint is too blunt (pilot 1).** With taint computed per
*session*, once the agent reads any untrusted tool output, every later
state-changing call is denied. On the banking suite a **perfect agent loses 9 of
16 tasks under A2 — a 56.2-point usefulness ceiling** (bootstrap 95% CI
[31.2, 81.2]); all 130 of 330 blocked calls came from the single
`tainted-state-change` rule. The *measured* gap on this run was smaller
(12.5 points, CI [-0.0, 31.2]) only because the Haiku baseline itself solved few
tasks. This is the PRD kill-criterion signal for session-level taint and the
direct motivation for **field-level taint** (kept in Phase 3).

**(b) Taint and decoder gaps (pilot 2 — found, then fixed).** Building and running
pilot 2 surfaced four concrete defects, each now fixed with a regression test:
- **No taint wiring.** The A2 arm sent a static `provenance=["trusted_user"]`, so
  the policy's `taint-unknown-destination` deny could never fire — A2 would have
  signed the attacker's transfer. Fixed in harness v1.1 (a trust map hashed into
  the bundle + monotonic session taint attached to every signing request).
- **No WETH `deposit()`/`withdraw()` handling** in the EVM decoder, which
  escalated benign wrap/unwrap as `unknown-call`. Fixed (CS-141 follow-up): the
  decoder recognises them only at the chain's canonical WETH.
- **Swap/multicall recipient** is the policy destination, not the called contract.
  Locked by a golden test in `internal/decode/evm`.
- **EIP-7702 / type-4** delegated signing wallet. `stopbard` now rejects type-4 and
  refuses to sign from a delegated wallet (CS-146).

**(c) A hard cap catches a fee drain even with its own policy removed.** Because
Stopbar binds the whole transaction and counts `gas_limit × max_fee` as USD spend,
the sliding-window limiter denies a fee-drain transaction even if the dedicated
`excessive-fee` Cedar rule is deleted. The deterministic control does not depend on
a specific rule being present. (Corpus: the fee-drain entry stays blocked; see
`make e2e`.)

## 3. What they could not measure: security against prompt injection

**Neither stock attacker landed a single success, even on the undefended arm,
against either victim.**

- **Pilot 1:** attack success rate **0% on A0 and 0% on A2** (both CIs [0, 0]).
  The attack did not succeed even without Stopbar, so the arm comparison is
  uninformative on security. The pilot's own conclusion was "uninformative on
  security; cost bounded between ~12 (weak agent) and ~56 (perfect agent) points."
- **Pilot 2:** competence gate **passed** (A0 16/20, within the pre-registered
  16–19/20) after two harness fixes — but the attack-validity gate **failed, A0
  0/25 across 0 scenarios**, and the run stopped before the defended arm. That
  0/25 is **not interpretable as victim robustness**:
  - the live run persisted only win/loss, so delivery, attacker text and victim
    replies were not saved for the 25 episodes (now fixed — see §4);
  - the only transcripts available (two S1 smoke episodes) show the attacker
    (Qwen, safety-trained) **partly refusing** — a mix of explicit refusals and
    weak, clumsy attempts — and **delivery for S2/S3/S5 was never verified** (18 of
    25 episodes used surfaces that were never smoke-tested).

So the honest reading is: with these attackers, no injection succeeded even with no
defence, on **Haiku 4.5** or **DeepSeek-V4.1-Flash**, and in pilot 2 the attacker
partly refused to attack. We make **no claim** about Stopbar's prompt-injection
defence from these runs.

## 4. Process lessons

1. **Scripted dry runs miss bugs that only appear on the model's code paths.** The
   pilot-2 dry run (scripted agent) reported Stage 1 competence 20/20; the first
   real model run scored 2/20 because two defects lived only in the model path
   (`benign_fn` never recorded the agent's submission; the agent had no address
   book). Both are now fixed and covered by fake-model tests plus a static
   solvability test.
2. **Always persist transcripts.** The pilot-2 0/25 is uninterpretable precisely
   because the live run saved no per-episode transcript. `live_run` now writes
   `transcripts.jsonl` (attacker text, agent tool calls, a delivery flag, victim
   reply, outcome per turn), so a future 0/25 is diagnosable for free.
3. **Gates and freezes stopped bad data from becoming claims three times** in
   pilot 2 alone: a signature held when the A2 smoke proved a denial was impossible
   (taint not wired); the competence gate stopped a 2/20 harness artifact before it
   could be read as "the model is incompetent"; the attack-validity gate stopped a
   0/25 before it could be read as "the model is robust." Pre-registration plus a
   hashed, frozen bundle is what made each stop mechanical rather than a judgement
   call.

## 5. What this changes for the product

The pattern to take seriously: **two pilots, two victims, and neither stock attack
landed even without a defence.** If that holds more generally, simple automated
prompt injection may matter less against current models than a T1-centric framing
assumes — so Stopbar's strongest, honest case is the part that **does not depend on
how robust the model is**:

- **Compromised requesters (T3)** — the Binance pattern, where no model is in the
  loop at all.
- **Agent mistakes (T2)** — the OpenClaw pattern, no adversary.
- **Hard loss caps, intent decoding, and a verifiable audit trail** that hold
  whatever the model does.

These are already demonstrated **deterministically** in the corpus replay
(`make e2e`): excessive-fee, unlimited-approval, delegatecall, min-out-zero and
nonce-replay all deny at the request path with no model involved. Prompt-injection
defence moves from the headline to **one input among several**, with field-level
taint kept in Phase 3 as the pre-registered comparison against the session-level
rule pilot 1 showed to be too blunt.

The research track is closed. It did its job: it found real design flaws, hardened
the harness, and produced an honest picture of where the threat actually is.
