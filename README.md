# Countersign

**An open-source intent firewall for signers.** Nothing gets signed — by an AI agent, a hot wallet, or an enterprise system — unless an independent policy engine countersigns it first.

> Status: pre-alpha. Foundations in progress — Go module, CI, core data model and RFC 8785 canonical hashing are in (CS-002/003/005/006). See [`docs/`](docs/) and the [task backlog](docs/TASKS.md).

```bash
make check   # vet + race tests
make fuzz    # fuzz the canonicaliser
```

---

## The problem in one line

Signers trust whoever calls them. In the largest recent incidents, **no key was stolen** — a trusted signer was fed a malicious request through a compromised upstream.

| Incident | Compromised upstream | Signer's response |
|---|---|---|
| Binance, Oct 2026 (~$6.3B, preliminary) | Engineer laptop → service container | Produced valid signatures |
| Bybit, Feb 2025 (~$1.5B) | Signing UI (blind signing) | Signed |
| Grok / Bankr, May 2026 | AI agent via encoded prompt injection | Signed |
| OpenClaw, Feb 2026 | AI agent error (no attacker) | Signed |
| Enterprise agents (ongoing) | Untrusted content / generated code | Executed |

A signature proves **who** authorised an action. Nothing today independently verifies **whether it should happen**.

## What Countersign does

Sits between the requester (agent, service, UI) and the signer, in a **separate trust domain**, and checks every action before it can be signed:

1. **Bound the loss** — value- and velocity-caps per wallet, chain, asset, agent. Draining ten chains in minutes becomes architecturally impossible.
2. **Check provenance** — did this request originate from untrusted content (a webpage, an NFT, an email), a freshly deployed workload, or an unusual service? Taint tracking for agents; deploy-correlation for infrastructure.
3. **Render intent independently** — decode the action into plain language on a separate channel. Kills blind signing.
4. **Escalate** — out-of-pattern or high-value actions require M-of-N human approval.
5. **Prove it** — tamper-evident, hash-chained audit log of every decision.
6. **Learn from every attack** — an open attack corpus; every real incident becomes a regression test.

## Who it's for (in order)

1. **Developers giving AI agents wallets** (crypto beachhead — fast feedback, real losses today).
2. **Platform/security teams running enterprise agents**, especially code-mode agents that execute generated scripts.
3. **Custodians and exchanges** protecting hot wallets (year 2).

## What it is not

- Not a wallet or a key custodian (v1 wraps existing signers).
- Not a prompt-injection classifier. Deterministic controls first; ML signals are inputs, never the last line.
- Not unproven by design: every control is rated against a threat tier (injected model, agent error, compromised requester, scheming agent), and the research track measures it on an external benchmark.
- Not a blockchain. Borrows the wallet pattern (keys, policy, signed logs) without a chain.

## Docs

| Doc | Purpose |
|---|---|
| [PRD](docs/PRD.md) | Problem, users, requirements, metrics, phases, kill criteria |
| [HLD](docs/HLD.md) | Architecture, trust boundaries, flows, threat model |
| [LLD](docs/LLD.md) | Data models, policy language, algorithms, APIs |
| [TASKS](docs/TASKS.md) | Full build backlog with acceptance criteria |
| [Attack corpus](corpus/) | Schema + seed attacks |
| [Spec](spec/) | Wire schemas, fixtures, audit-hash v1 |

## Roadmap (summary)

| Phase | Window | Outcome |
|---|---|---|
| 0 Foundations | Weeks 0–2 | Repo, CI, core data model, decision contract |
| 1 Agent-wallet MVP | Weeks 2–8 | Gatekeeper proxy for EVM agent wallets; replay suite blocks seed attacks |
| 1R Research track | Weeks 4–10 (parallel) | AgentDojo eval: no defence vs LLM monitor vs Countersign vs both; adaptive attacker; scheming-agent setting; public write-up |
| 2 Corpus & community | Weeks 8–12 | Open corpus, contribution flow, public launch |
| 3 Code-mode agents | Months 3–9 | Policy on every binding call inside agent sandboxes |
| 4 Custody grade | Year 2 | Co-signer mode (Safe guard / MPC share), HSM/TEE, deploy correlation |

Windows assume full-time focus. Build the **thin slice** first (23 tasks, ~41 build days, labelled `thin-slice`): the shortest path to a public demo blocking the seed attacks.

## Track work

Backlog lives in [`docs/TASKS.md`](docs/TASKS.md) and [`docs/tasks.csv`](docs/tasks.csv). To create GitHub issues and milestones from it:

```bash
gh auth login
./scripts/create_github_issues.sh <owner>/<repo>
```

## License

Apache-2.0. See [LICENSE](LICENSE).
