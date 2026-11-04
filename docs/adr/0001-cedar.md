# ADR 0001: Cedar as the policy language

- Status: **Accepted (go)**, with the conditions below
- Date: 2026-11-04
- Task: CS-007 (PRD §13 Q1)
- Evidence: `internal/policy/cedar_spike_test.go` (runs in CI)

## Context

LLD §5 proposes Cedar for policy, with Stopbar's three outcomes layered on top
of Cedar's permit/forbid through `@outcome` annotations (deny > escalate >
allow, default deny). The spike set out to answer four questions with
`cedar-go`: whether decimal and set context work, whether the annotation
approach works, whether it fits the 2 ms policy budget (LLD §13), and whether
it fails safely.

## Decision

Use Cedar through `github.com/cedar-policy/cedar-go`, **pinned at v1.8.0**.
v1.9.0 requires Go 1.26, and the module targets Go 1.24.

The combiner is the one from LLD §5.2. Forbid policies with
`@outcome("escalate")` go into a separate policy set. Everything else goes
into the main set. The main set is evaluated first: a Cedar `Deny` there means
deny, which includes the case where no permit matched. A forbid firing in the
escalate set means escalate. Otherwise the outcome is allow.

## Findings

| # | Finding | Consequence |
|---|---|---|
| 1 | **Evaluation errors fail open.** `Authorize` skips any policy whose condition errors (a missing attribute or a wrong type) and records the error in `Diagnostic.Errors`. A forbid that errors therefore doesn't fire, and raw Cedar returns `Allow`. | The engine **must** map any `Diagnostic.Errors` in either set to `deny` / `FAIL_CLOSED_POLICY`. This is non-negotiable and is pinned by `TestSpikeEvalErrorsAreSkipped`. |
| 2 | **`@id` is not the PolicyID.** `NewPolicySetFromBytes` names policies `policy0..N`, and `@id("…")` is only an annotation. | The loader (CS-111) maps `@id` to the PolicyID and rejects duplicate or missing IDs. Without this, `Decision.policy_ids` and corpus `expected.policy_ids` would carry meaningless names. |
| 3 | **Decimals have no `>` operator.** `context.x > decimal("0.20")` is a type error, so decimals must use `.greaterThan()`, `.lessThan()` and the other methods. The starter policy and LLD §5.3 had this wrong. | Both are fixed. Combined with finding 1, the bad policy would have denied *every* request, which is safe but useless. Bundles must pass schema validation before activation. |
| 4 | **Cedar decimals are int64 with 4 fractional digits** (about ±9.2e14), and the parser requires a `.`, so `"100"` and `"1e3"` are rejected. | Only USD-denominated values go to Cedar. Raw units such as wei never do, and raw-unit caps stay in the limiter (`big.Int`). The enricher needs an explicit conversion from model decimal strings that rounds toward the stricter outcome: up for amounts and percentages. |
| 5 | `Set<String>` with `contains` / `containsAny` works as needed for `taint` and `flags`. | None. |
| 6 | The schema validator (`x/exp/schema/validate`) type-checks policies at load time and requests before evaluation. It caught finding 3 and rejects missing or ill-typed context. | We use it, but it lives under `x/exp`, which has **no semver guarantee**. We wrap it behind `internal/policy` and keep the runtime check from finding 1 regardless. |
| 7 | Two-set evaluation of the starter pack takes about **1 µs/op** (26 allocs) on an M-series laptop. | That's roughly 2000× under the 2 ms budget. |
| 8 | `base-permit` omits `approve` and `tool_call`, so all approvals and tool calls are default-denied. | This fails safe, but it's a gap in the policy pack, not in the engine. The tool-call pack is CS-502 work. |

## Conditions on "go"

1. Treat any evaluation error as fail-closed (finding 1).
2. The loader validates every bundle against the schema and enforces unique `@id`s and a known `@outcome` (`deny`/`escalate`, with deny as the default on forbid). Annotations on permit policies are rejected.
3. Cedar stays out of the trusted hashing and signing core. Bundle hashing (LLD §5.4) uses `internal/canon` over the policy source bytes, not cedar-go's re-serialisation.
4. Upgrading cedar-go is a reviewed change. The spike tests and the corpus replay are the regression gate.

## Alternatives considered

OPA/Rego is more expressive but has no built-in typed schema validation, a
heavier runtime and a steeper authoring curve. A hand-rolled DSL means
spending design time on a language instead of on controls. Neither gains
anything over Cedar once findings 1 to 4 are handled.
