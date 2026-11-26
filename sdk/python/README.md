# Stopbar Python SDK

An **intent firewall** for an AI agent's actions: nothing gets signed or executed
unless an independent policy engine (stopbard) in a separate trust domain clears
it first. This SDK is the in-process client agent builders use to send actions to
Stopbar and act on the decision.

The core client is **stdlib-only** — `pip install stopbar` pulls no third-party
dependencies. The AgentKit wallet provider and signed approvals are optional
extras.

## Install

```bash
pip install stopbar              # core client
pip install "stopbar[wallet]"    # + the Coinbase AgentKit gatekeeper wallet provider
pip install "stopbar[approver]"  # + signing escalation approvals/rejects (CS-151)
```

## Use

```python
from stopbar import Client, StopbarDenied, StopbarEscalated

sb = Client(
    "http://127.0.0.1:7777",
    api_key="stopbar_sk_...",      # from `stopbar keygen api-key`
    tenant="demo", agent_id="wallet-agent",
)

action = sb.evm_tx(
    chain_id=8453, from_addr=my_wallet, to=recipient, value_wei="5000000000000000000",
    tx_nonce="0", gas_limit="21000", max_fee_per_gas="200000000", max_priority_fee_per_gas="100000000",
)

try:
    decision = sb.evaluate(action, labels=["untrusted_web"])  # provenance taint
    broadcast(decision.signed_tx)          # gatekeeper mode: Stopbar already signed it
except StopbarDenied as d:
    print("forbidden:", d.reasons)         # for any caller, whoever asks (403)
except StopbarEscalated as e:
    print("needs approval:", e.request_id) # (202) hold it for a human
    approved = sb.approve(e.request_id, "/path/to/approver.key")  # signs locally, re-evaluates on quorum
    broadcast(approved.signed_tx)
```

**mTLS (service mode).** Against a stopbard serving https with client-certificate
auth (CS-103), present the workload's certificate instead of an API key. Its
SPIFFE ID is the identity, and `tenant`/`agent_id` must match what the operator
mapped it to:

```python
sb = Client("https://stopbar.internal:7777", tenant="demo", agent_id="wallet-agent",
            client_cert="bot.crt", client_key="bot.key", ca_cert="stopbar-ca.pem")
```

**The HTTP status alone is safe to act on:** 200 is allow and only allow, 202 is
escalate, 403 is deny. `evaluate` returns the `Decision` on an allow and raises a
typed error otherwise, so a missed check can never read a deny as an allow.

### Reservations and escalations

An allow reserves cap capacity. In advisory mode (you sign elsewhere) report
what happened, so caps count real spend and abandoned actions free theirs:

```python
d = sb.evaluate(action)
sb.commit(d.request_id, tx_hash)       # broadcast: the spend counts (retry-safe)
sb.release(d.request_id, "cancelled")  # abandoned: the cap is freed (retry-safe)
```

An escalation waits for a human (default 15 minutes, then it expires as a deny).
Approving and rejecting are Ed25519-signed, never an API call alone (CS-151,
spec/approval-signature-v1.md): the SDK fetches what to sign from Stopbar,
signs it locally with an approver key — the private key never leaves this
process — and submits the signature. A quorum of **distinct** approver keys
(M-of-N, at least 2 in production) is required; one signature alone leaves it
pending (still a 202 `StopbarEscalated`):

```python
st = sb.poll(request_id)               # .state: pending / allowed / denied / expired
if st.allowed:
    use(st.decision.token)             # or st.decision.signed_tx in gatekeeper mode

# approver_key is a path to a key file from `stopbar approver keygen`
# (or stopbar.approval.write_key_file), or raw 32-byte Ed25519 seed bytes.
sb.approve(request_id, approver_key_1)  # 1 of 2: still escalated (StopbarEscalated)
sb.approve(request_id, approver_key_2)  # 2 of 2: quorum met, re-evaluates against current state
sb.reject(request_id, approver_key_1)   # one valid reject denies outright, regardless of quorum
```

Refusals raise `StopbarRequestError` with `.code` (`NOT_FOUND`, `CONFLICT`,
`ALREADY_RESOLVED`, `RESERVATION_EXPIRED`, `DUPLICATE_VOTE`, …). The CLI
equivalents are `stopbar approve <id> --approver-key FILE` and
`stopbar reject <id> --approver-key FILE`.

### Provenance labels (taint)

A `Session` accumulates labels as the agent encounters untrusted input; they ride
on every request and only ever grow (taint is monotonic in v1):

```python
s = sb.session(["trusted_user"])
s.add(page_text, "untrusted_web", ref=url) # after the agent reads web content
s.evaluate(action)                         # both labels (and the source) attached
```

`add` scans every input not labelled `trusted_*` for encoded content — base64,
hex, Morse, ROT-n and zero-width characters — and adds `decoded` when it finds
any (the Grok/Bankr pattern: an instruction hidden in Morse in on-chain content).
Base64 and hex count only when they decode to readable text, so addresses, hashes
and calldata don't trip it. `stopbar.detect_encodings(text)` exposes the detector.

> Labels are *claims* from the requester. In v1 they hold against an injected
> model with an honest harness (T1); against a compromised requester (T3) only
> the controls inside Stopbar — caps, allowlists, the circuit breaker and
> gatekeeper mode — hold.

### AgentKit wallet provider

```python
from stopbar import Client
from stopbar.wallet import StopbarWalletProvider

provider = StopbarWalletProvider(
    client=Client("http://127.0.0.1:7777", api_key="stopbar_sk_...", tenant="demo", agent_id="wallet-agent"),
    rpc_url="http://127.0.0.1:8545", address=my_wallet, chain_id=8453,
    provenance=lambda: ["untrusted_web"],
)
```

The provider holds no key: stopbard signs (gatekeeper mode), so an injected or
compromised agent can't sign around the policy. Off-chain signatures are refused.

**AgentKit telemetry is off.** AgentKit posts the wallet address, network and
every action name to Coinbase analytics and has no opt-out. Importing
`stopbar.wallet` stubs both of its call sites (wallet provider initialisation
and the action decorator) for the whole process, so no AgentKit provider or
action in it phones home.

## License

Apache-2.0.
