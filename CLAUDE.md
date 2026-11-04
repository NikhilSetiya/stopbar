# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Stopbar is an open-source **intent firewall for signers**: nothing gets signed or executed (by an AI agent, hot wallet or enterprise system) unless an independent policy engine in a separate trust domain clears it first. Thesis: the attack surface has moved from the key to the request path, since in the big recent incidents no key was stolen. Instead, a trusted signer was fed a malicious request.

Status is pre-alpha. Implemented so far:

- `internal/model`: wire types.
- `internal/canon`: RFC 8785 JCS and hashing.
- `internal/gateway`: the HTTP API with strict request checks. See LLD §4 for check order and error codes.
- `internal/engine`: pipeline orchestration with fail-closed mapping and invariants between stages (LLD §2, §12). It consumes components through interfaces; the real ones arrive in CS-111/121/141/161/171.
- `internal/decision`: the payload binding (`PayloadHash`).
- `internal/policy`: Cedar bundle loader and outcome combiner (CS-111/112, LLD §5). The spike tests stay as a regression gate on cedar-go behaviour.
- `internal/limiter`: sliding-window caps with reserve/commit/release, written to bbolt before being applied (CS-121/122, LLD §7.3a). Its property test is the acceptance bar.
- `internal/devstub`: **dev-only** stand-ins for the decoder, price/balance enricher, signer and audit log. Each one names the task that replaces it. Its signer issues tokens that every verifier rejects.

The Cedar spike (`internal/policy`) and the decision-token signer/verifier reference exist only as tests. Every other `internal/*` package is a placeholder `doc.go` whose responsibilities are defined in LLD §1. `cmd/stopbard` serves the gateway on loopback only until auth exists (CS-103). Without flags it has no engine, and `/v1/evaluate` answers 503. `-state-dir` makes nonces and limiter state durable. `stopbard -dev-world <setup.json>` runs the real gateway, engine, limiter and policy bundle, with devstub components seeded from a corpus-style `setup` (which may set `limits`). Corpus entries may be `requests` sequences with `expected.at_step`. `make e2e` replays every corpus attack through it over HTTP (`scripts/e2e_corpus.py`) and requires the expected status and policy IDs.

## Commands

```bash
make check        # go vet + go test -race -count=1 ./...
make build        # go build ./...
make fmt          # gofmt -w .   (CI fails on any unformatted file)
make fuzz         # 60s fuzz of the canonicaliser (FuzzTransformIdempotent)
make e2e          # scripts/e2e.sh: CI mirror + every end-to-end check that exists so far

go test -race -run TestRFC8785NumberVectors ./internal/canon/   # single test
python3 scripts/tasks.py                                         # regenerate backlog
```

**Run `make e2e` after every build step**, and extend `scripts/e2e.sh` in the same change that adds a pipeline stage (engine evaluate, corpus replay, audit verify). On macOS, `make` and `-race` need the Xcode license accepted. Without it, `./scripts/e2e.sh` falls back to non-race tests. e2e fails if golangci-lint isn't exactly the pinned version, and it prints the install command.

CI (`.github/workflows/ci.yml`) runs gofmt, vet, build, race tests, 30s fuzz smokes (canonicaliser, gateway), govulncheck v1.9.0, golangci-lint v2.15.0, and the **corpus replay over HTTP** (`scripts/e2e_corpus.py`). The replay is a step in the required `go` job, so a PR that stops blocking an attack cannot merge. Put new required checks inside existing jobs: a new job is only enforced once its name is added to branch protection. The `corpus` workflow runs `scripts/validate_corpus.py`, which checks `corpus/attacks/*.yaml` (and each entry's `request`) and `spec/fixtures/*.json` against the JSON schemas. Keep both green. The module is `github.com/NikhilSetiya/stopbar` on Go 1.26 (`go 1.26.0`, `toolchain go1.26.10`). CI's setup-go reads the toolchain from `go.mod`, and locally `GOTOOLCHAIN=auto` fetches it. Tool versions are exact pins, never `@latest`, and live both in `ci.yml` and at the top of the lint section of `scripts/e2e.sh`. GitHub Actions are pinned to commit SHAs with a version comment. Dependabot proposes updates weekly. Before taking one, check that its `go` requirement doesn't exceed `go.mod`.

## Source of truth

The design docs are authoritative and detailed. Read the relevant section before implementing a component:

- `docs/PRD.md`: problem, threat tiers (§2.4), requirements (`FR-*`/`NFR-*`), metrics, phases, kill criteria
- `docs/HLD.md`: architecture, enforcement modes, trust boundaries, threat model, research eval architecture (§8a)
- `docs/LLD.md`: Go interfaces (§2), data model (§3), Cedar design (§5), limiter (§7), taint (§8), decision tokens (§10), fail-closed codes (§12), testing strategy (§16), research harness (§18)
- `spec/`: wire schemas, fixtures, `audit-hash-v1.md` and `decision-token-v1.md` (the gatekeeper binding: `payload_hash` = sha256 of the JCS-canonical action, never keccak). `spec/vectors/` is generated by `go test ./internal/decision -run TestDecisionTokenVectors -update`. Review the diff. The Go structs in `internal/model` are the contract, and `spec/schemas/*.schema.json` mirror them for non-Go clients. Change both together.
- `docs/TASKS.md` and `docs/tasks.csv` are **generated**. Edit `scripts/tasks.py`, run it, and commit both outputs.

A design change updates PRD/HLD/LLD in the same PR (plus an ADR in `docs/adr/`), and new work gets a task in `scripts/tasks.py`.

## Architecture

The pipeline is orchestrated by an `Engine` (LLD §2):

gateway → normalize → decode intent (`decode/evm`) → enrich (price, balance, velocity, provenance) → policy (Cedar) → limiter (reserve/commit caps) → decision signer (JWS / EIP-712) → hash-chained audit log

- **Fail closed everywhere.** Each component returns typed errors. The engine maps any non-domain error, panic or timeout to `deny` with `FAIL_CLOSED_<COMPONENT>` (LLD §12), and no decision may go unaudited.
- **The HTTP status alone is safe to act on:** 200 is allow and only allow, 202 is escalate, 403 is deny. Every response with a decision carries the full Decision in its body.
- **Freshness:** the nonce is consumed before evaluation. **Never add a clock override to `stopbard`**, because a settable clock turns TTL checks off. Injected clocks belong in unit tests only, and the corpus replay rewrites `issued_at`/nonce per run (`scripts/corpus_template.py`).
- **CS-103 (auth) is a hard gate before `stopbard` listens on any non-loopback address.** Agent and tenant caps can be spoofed until then. Wallet caps can't, because they're bound to the signing address.
- **Policy outcome precedence:** deny > escalate > allow, with default deny.
- **Limiter** reserves on evaluate and then commits or releases (`Engine.Commit/Release`), so caps hold across concurrent requests.
- **Enforcement modes** (HLD §3) determine real security. *Advisory* is bypassable. *Gatekeeper* (the Phase 1 default) means Stopbar holds the signer credential. *Co-signer* (Phase 4) means the signer requires Stopbar's signature.
- **Markets, in order:** EVM agent wallets → enterprise/code-mode agent tool calls → custody/exchanges (co-signer).

## Decisions already made (don't relitigate without reason)

- **The trusted core is stdlib-only.** Anything that feeds a hash or signature takes no third-party dependencies, which is why JCS is hand-written in `internal/canon`.
- **Amounts are decimal strings, never JSON numbers**, because wei exceeds 2^53. Never route them through float64.
- **Audit hash v1** = `sha256(JCS({v, seq, ts, type, body, prev_hash}))`, not raw concatenation (`spec/audit-hash-v1.md`, `canon.RecordHash`).
- **Threat tiers:** T1 is an injected model with an honest harness, T2 is agent error, T3 is a compromised requester, and T4 is a scheming agent. Every control is rated by the tier it holds at. v1 SDK taint holds only at T1. Against T3/T4, only caps, allowlists, the circuit breaker and gatekeeper mode hold.
- **The v1 trust boundary** treats the harness (agent framework + SDK) as trusted and the model as untrusted.
- **Taint labels only restrict.** Absence of taint is never proof of safety.
- **ML is never a blocking control in v1.** An LLM monitor runs only in shadow mode, for research.
- **Cedar** is the policy language (`docs/adr/0001-cedar.md`, accepted). cedar-go is the first non-stdlib dependency and stays outside the hashing/signing core. Its pitfalls are pinned by `internal/policy/cedar_spike_test.go`:
  - cedar-go **skips policies that error**, so the engine must map any `Diagnostic.Errors` to `FAIL_CLOSED_POLICY`.
  - `@id` must be mapped to the PolicyID by the loader.
  - Decimals compare with `.greaterThan()` etc., not `>`.
  - Cedar decimals take USD values only, never wei.
- The project was renamed from Countersign. **Task IDs stay `CS-`.**

## Conventions

- Commits follow the form `CS-<id>: <summary>`, one task per commit where possible. The `thin-slice` issue label marks the shortest path to a public demo.
- Tests are table-driven. Use property tests for the limiter, and fuzz the decoders and the canonicaliser.
- `model` types expose `Validate()`, which reports every problem at once rather than stopping at the first. Round-trip tests run against `spec/fixtures`.
- The highest-value outside contribution is an attack in `corpus/attacks/` (see `corpus/README.md`). Every real incident becomes a regression test.

## Working with the maintainer

Be brief and direct. Challenge weak reasoning. Prefer small, verified increments over big plans.
