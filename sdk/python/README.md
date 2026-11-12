# Stopbar Python SDK

An **intent firewall** for an AI agent's actions: nothing gets signed or executed
unless an independent policy engine (stopbard) in a separate trust domain clears
it first. This SDK is the in-process client agent builders use to send actions to
Stopbar and act on the decision.

The core client is **stdlib-only** — `pip install stopbar` pulls no third-party
dependencies. The AgentKit wallet provider is an optional extra.

## Install

```bash
pip install stopbar            # core client
pip install "stopbar[wallet]"  # + the Coinbase AgentKit gatekeeper wallet provider
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
    approved = sb.approve(e.request_id)    # re-evaluates against current state
    broadcast(approved.signed_tx)
```

**The HTTP status alone is safe to act on:** 200 is allow and only allow, 202 is
escalate, 403 is deny. `evaluate` returns the `Decision` on an allow and raises a
typed error otherwise, so a missed check can never read a deny as an allow.

### Provenance labels (taint)

A `Session` accumulates labels as the agent encounters untrusted input; they ride
on every request and only ever grow (taint is monotonic in v1):

```python
s = sb.session(["trusted_user"])
s.add_label("untrusted_web")               # after the agent reads web content
s.evaluate(action)                         # both labels attached
```

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

## License

Apache-2.0.
