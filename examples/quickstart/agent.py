"""Quickstart sample agent (CS-198): pays through the Stopbar Python SDK from the
gatekeeper wallet `stopbar init` generated, and broadcasts what Stopbar signs to
a local Anvil chain. The README quickstart runs it; scripts/quickstart.sh runs
that README in CI.

    agent.py            the journey: allow (signed, broadcast), a large payment
                        that escalates, and two corpus attacks; prints
                        `export PAYMENT=... POISONED=...` for the approvers
    agent.py resume ID  after the approvers sign: poll the escalation, broadcast
                        the signed tx Stopbar returned, commit it

Env: STOPBAR_URL, STOPBAR_KEY, STOPBAR_TENANT, STOPBAR_WALLET (from init's
output), ANVIL_URL (default http://127.0.0.1:8545). Amounts fit init's --chain
dev world (1 ETH at $3,500, 1,000 USDC; $5,000/h wallet cap). Exits non-zero
if any outcome differs from the expected one. Stdlib + the SDK only.
"""
import json
import os
import sys
import time
import urllib.request

from stopbar import Client, StopbarDenied, StopbarEscalated

WALLET = os.environ["STOPBAR_WALLET"]
ANVIL = os.environ.get("ANVIL_URL", "http://127.0.0.1:8545")
BOB = "0x000000000000000000000000000000000000b0b0"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"  # in init's dev world
# CS-2026-0011: the vendor the README allowlists, and the attacker's vanity look-alike.
LOOKALIKE = "7a25e0f3b9c4a8d27165e3f0a9b8c7d6e5f40c21"
# CS-2026-0008: a Safe MultiSend batch of a 25 USDC payment and approve(attacker, 2^256-1), the
# corpus calldata with its fixture token (0x3333…) swapped for init's USDC, which the dev world prices.
SAFE = "0x6666666666666666666666666666666666666666"
HIDDEN_APPROVAL = "0x6a761202000000000000000000000000a238cbeb142c10ef7ad8442c6d1f9e89e07e776100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001848d80ff0a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000013200333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000017d784000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000009f30000000000000000000000000000000000c21ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".replace(
    "3333333333333333333333333333333333333333", USDC[2:])

sb = Client(os.environ["STOPBAR_URL"], api_key=os.environ["STOPBAR_KEY"],
            tenant=os.environ.get("STOPBAR_TENANT", "demo"), agent_id="wallet-agent")
failures = 0


def expect(ok, what):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    failures += not ok


def rpc(method, *params):
    req = urllib.request.Request(ANVIL, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def broadcast(signed_tx):
    """Send the tx Stopbar signed and wait for its receipt; True if it succeeded on-chain."""
    h = rpc("eth_sendRawTransaction", signed_tx)
    for _ in range(50):
        rc = rpc("eth_getTransactionReceipt", h)
        if rc:
            return h, rc["status"] == "0x1"
        time.sleep(0.1)
    return h, False


def evaluate(to, value_wei="0", data="0x", gas="21000"):
    """The whole unsigned EIP-1559 tx, nonce from the chain; Stopbar binds every field."""
    nonce = int(rpc("eth_getTransactionCount", WALLET, "pending"), 16)
    action = sb.evm_tx(chain_id=8453, from_addr=WALLET, to=to, value_wei=value_wei, data=data, tx_nonce=str(nonce),
                       gas_limit=gas, max_fee_per_gas="2000000000", max_priority_fee_per_gas="1000000000")
    try:
        return sb.session(["trusted_user"]).evaluate(action)
    except (StopbarDenied, StopbarEscalated) as e:
        return e  # .decision, .reasons; StopbarUnavailable/AuthError propagate: fail closed, nothing is broadcast


def outcome(r):
    return (r.outcome, r.reasons) if hasattr(r, "outcome") else (r.decision.get("outcome"), r.reasons)


def journey():
    print("1. pay Bob 0.01 ETH:")
    r = evaluate(BOB, "10000000000000000")
    expect(outcome(r)[0] == "allow" and r.signed_tx, f"HTTP 200 allow, signed by stopbard ({outcome(r)})")
    h, ok = broadcast(r.signed_tx)
    expect(ok, f"broadcast on Anvil: {h}, Bob has {int(rpc('eth_getBalance', BOB, 'latest'), 16) / 1e18} ETH")
    sb.commit(r.request_id, h)

    print("2. pay Bob 0.5 ETH (half the balance):")
    pay = evaluate(BOB, "500000000000000000")
    expect(outcome(pay) == ("escalate", ["large-share-of-balance"]), f"HTTP 202 escalate, nothing signed {outcome(pay)}")

    print("3. corpus CS-2026-0011, address poisoning: 100 USDC to a look-alike of the allowlisted vendor:")
    poisoned = evaluate(USDC, data="0xa9059cbb" + LOOKALIKE.rjust(64, "0") + hex(100_000_000)[2:].rjust(64, "0"), gas="100000")
    expect(outcome(poisoned) == ("escalate", ["address-poisoning"]), f"HTTP 202 held for a human, nothing signed {outcome(poisoned)}")

    print("4. corpus CS-2026-0008: an unlimited approval hidden inside a Safe batch next to a 25 USDC payment:")
    r = evaluate(SAFE, data=HIDDEN_APPROVAL, gas="300000")
    expect(outcome(r) == ("deny", ["unlimited-approval"]), f"HTTP 403 deny {outcome(r)}")

    print(f"export PAYMENT={pay.decision.get('request_id')} POISONED={poisoned.decision.get('request_id')}")


def resume(request_id):
    print(f"resume {request_id}: poll the escalation")
    st = sb.poll(request_id)
    expect(st.allowed and st.decision and st.decision.signed_tx, f"state {st.state}: the approvers' quorum released the signed tx")
    h, ok = broadcast(st.decision.signed_tx)
    expect(ok, f"broadcast on Anvil: {h}, Bob has {int(rpc('eth_getBalance', BOB, 'latest'), 16) / 1e18} ETH")
    expect(sb.commit(request_id, h).get("state") == "committed", "committed to the limiter")


if len(sys.argv) == 3 and sys.argv[1] == "resume":
    resume(sys.argv[2])
elif len(sys.argv) == 1:
    journey()
else:
    sys.exit("usage: agent.py [resume REQUEST_ID]")
sys.exit(1 if failures else 0)
