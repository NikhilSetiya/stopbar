# `make demo` — product walking skeleton

A single command that walks Stopbar end to end on an Anvil fork of Base, so the
gaps between "the engine works" and "a developer can deploy it" are visible, not
guessed. **DEV MODE, dev keys, stub price/balance data — not for real funds.**

```bash
make demo        # needs Foundry (anvil): https://getfoundry.sh
```

It builds the binaries, starts `stopbard` **from a config file** (not dev flags),
and runs a scripted AgentKit agent through:

| Step | Action | Expected |
|---|---|---|
| 1 | Pay an allowlisted contact | **ALLOW** — stopbard signs, the agent broadcasts, the recipient balance changes on-chain |
| 2 | Tainted transfer to an unknown address | **DENY** `taint-unknown-destination` |
| 3 | Transfer > 20% of balance | **ESCALATE** `large-share-of-balance` |
| 4 | Unlimited token approval | **DENY** `unlimited-approval` |
| 5 | **Restart stopbard** mid-run | nonce set persists (`NONCE_REPLAYED`) and the per-wallet cap persists (`CAP_EXCEEDED`) |
| 6 | `stopbar audit verify --require-covered` | **OK** over the whole log, across the restart |

The driver (`research/walletagent/demo.py`) prints each step, times the journey
against the PRD's 30-minute goal, labels every stub and dev key, and lists the
gaps and hidden-knowledge steps it hit. A non-blocking `demo` CI job runs it.

## Gaps this exposes (the point of the skeleton)

Mapped to the product roadmap:

- **No auth; loopback only.** The agent and stopbard talk over an unauthenticated
  loopback socket. → **CS-103** (the hard gate before any non-loopback address).
- **The world file is the stub.** Prices, balances and the allowlist are hard-coded
  `internal/devstub` data, not live. → **CS-131/132/133** (real prices, balances,
  destination registry).
- **No product SDK.** The AgentKit integration (`StopbarWalletProvider`) and the
  driver live in `research/walletagent/` and reuse its Python venv; there is no
  installable package a developer would adopt. → **CS-181/183**.
- **Config wraps dev flags only.** `stopbard -config` is a thin first surface over
  the existing flags; it still selects dev components. A production config needs
  auth, a real (KMS/HSM) key provider and real enrichers.
- **No `stopbar keygen`.** A persistent decision key — required for audit-verify
  across a restart — has no CLI; the demo hand-writes stopbard's tagged key-file
  format. A small productionization task.
- **`audit verify` is two steps.** You must save `GET /v1/keys` to a file and pass
  `--keys`; there is no one-shot verify.
- **The demo CI job is heavier and more external** than the required jobs (it needs
  Foundry and a Base fork over the network), so it is non-blocking until added to
  branch protection.

What the skeleton proves already: the allow→broadcast path, the deny/escalate
reason codes, cap and nonce **persistence across a restart**, and an offline audit
trail that verifies over the whole run — all deterministic, with no model in the
loop.
