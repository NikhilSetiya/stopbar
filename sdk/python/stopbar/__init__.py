"""Stopbar Python SDK — an intent firewall for an agent's actions.

    from stopbar import Client, StopbarDenied, StopbarEscalated

    sb = Client("http://127.0.0.1:7777", api_key="stopbar_sk_...", tenant="demo", agent_id="wallet-agent")
    try:
        decision = sb.evaluate(sb.evm_tx(chain_id=8453, from_addr=..., to=..., tx_nonce="0",
                                         gas_limit="21000", max_fee_per_gas="...", max_priority_fee_per_gas="..."),
                               labels=["untrusted_web"])
        broadcast(decision.signed_tx)        # gatekeeper mode: Stopbar signed it
    except StopbarDenied as d:
        ...                                  # forbidden, for any caller
    except StopbarEscalated as e:
        later = sb.approve(e.request_id)     # once a human approves

The AgentKit wallet provider lives in ``stopbar.wallet`` and needs the 'wallet'
extra (``pip install stopbar[wallet]``); the core client above is stdlib-only.
"""
from .client import Client, Decision, Session
from .errors import (
    StopbarAuthError,
    StopbarDecisionError,
    StopbarDenied,
    StopbarError,
    StopbarEscalated,
    StopbarUnavailable,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Decision",
    "Session",
    "StopbarError",
    "StopbarDecisionError",
    "StopbarDenied",
    "StopbarEscalated",
    "StopbarUnavailable",
    "StopbarAuthError",
    "__version__",
]
