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
        st = sb.poll(e.request_id)           # pending / allowed / denied / expired
        later = sb.approve(e.request_id)     # once a human approves (approver key)

    # Advisory mode: report what happened to an allow's reservation.
    sb.commit(decision.request_id, tx_hash)  # broadcast: the spend counts
    sb.release(decision.request_id)          # abandoned: the cap is freed

The AgentKit wallet provider lives in ``stopbar.wallet`` and needs the 'wallet'
extra (``pip install stopbar[wallet]``); the core client above is stdlib-only.
"""
from .client import Client, Decision, EscalationStatus, Session
from .errors import (
    StopbarAuthError,
    StopbarDecisionError,
    StopbarDenied,
    StopbarError,
    StopbarEscalated,
    StopbarRequestError,
    StopbarUnavailable,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Decision",
    "EscalationStatus",
    "Session",
    "StopbarError",
    "StopbarDecisionError",
    "StopbarDenied",
    "StopbarEscalated",
    "StopbarUnavailable",
    "StopbarAuthError",
    "StopbarRequestError",
    "__version__",
]
