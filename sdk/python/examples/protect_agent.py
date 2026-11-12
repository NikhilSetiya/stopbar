"""Protect an agent's wallet actions end-to-end with the Stopbar SDK.

Run against a stopbard started like the demo (gatekeeper mode, auth on). This is
the example the CS-182 acceptance ("the same example in Python passes") points
at: an allowed payment goes through, a forbidden one is denied, and a large one
escalates and is then approved.

    STOPBAR_URL=http://127.0.0.1:7777 STOPBAR_KEY=stopbar_sk_... \
    STOPBAR_APPROVE_KEY=stopbar_sk_... python examples/protect_agent.py
"""
import os

from stopbar import Client, StopbarDenied, StopbarEscalated

WALLET = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x000000000000000000000000000000000000b0b0"


def main() -> None:
    sb = Client(os.environ["STOPBAR_URL"], api_key=os.environ.get("STOPBAR_KEY"),
                tenant=os.environ.get("STOPBAR_TENANT", "demo"), agent_id="wallet-agent")

    def pay(to: str, value_wei: str, nonce: str, labels=None):
        action = sb.evm_tx(chain_id=8453, from_addr=WALLET, to=to, value_wei=value_wei, tx_nonce=nonce,
                           gas_limit="21000", max_fee_per_gas="200000000", max_priority_fee_per_gas="100000000")
        try:
            d = sb.evaluate(action, labels=labels or ["trusted_user"])
            print(f"  ALLOW  -> signed_tx present: {bool(d.signed_tx)}")
        except StopbarDenied as d:
            print(f"  DENY   -> {d.reasons}")
        except StopbarEscalated as e:
            print(f"  ESCALATE -> {e.reasons}; request_id={e.request_id}")
            if os.environ.get("STOPBAR_APPROVE_KEY"):
                approver = Client(os.environ["STOPBAR_URL"], api_key=os.environ["STOPBAR_APPROVE_KEY"],
                                  tenant=sb.tenant, agent_id="operator")
                approved = approver.approve(e.request_id)
                print(f"  APPROVED -> outcome={approved.outcome}, signed_tx present: {bool(approved.signed_tx)}")

    print("pay Bob 0.01 ETH (allowlisted):"); pay(BOB, "10000000000000000", "0")
    print("pay unknown 0.5 ETH:"); pay("0x7c9e8a2b4d6f1030a5b8c2e4f6a1b3d5e7f90c2a", "500000000000000000", "1")
    print("send 5 ETH to Bob (large share):"); pay(BOB, "5000000000000000000", "1")


if __name__ == "__main__":
    main()
