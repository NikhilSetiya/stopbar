"""End-to-end: Coinbase AgentKit actions -> StopbarWalletProvider -> stopbard
(gatekeeper, holds the key) -> Anvil. No model is involved: this checks the
wiring, not an agent. Usage (from the repo root, after building bin/stopbard):

  research/walletagent/.venv/bin/python research/walletagent/e2e_wallet.py bin/stopbard
"""
import json, os, socket, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(__file__))
from coinbase_agentkit import AgentKit, AgentKitConfig, wallet_action_provider  # noqa: E402
from web3 import Web3  # noqa: E402

from stopbar_wallet import StopbarBlocked, StopbarWalletProvider  # noqa: E402

# Anvil's public default accounts (well known; stopbard accepts them only with -dev-world).
KEY0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ADDR0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ADDR1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # known destination
STRANGER = "0x9f30000000000000000000000000000000000c21"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main(stopbard: str) -> int:
    fails = []

    def check(name, ok, detail=""):
        print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")
        if not ok:
            fails.append(name)

    port = free_port()
    anvil = subprocess.Popen(["anvil", "--port", str(port), "--silent"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tmp = tempfile.mkdtemp()
    world, wallet = os.path.join(tmp, "world.json"), os.path.join(tmp, "wallet")
    json.dump({"known_destinations": [ADDR1.lower()], "balances": {"ETH": "10000", "USDC": "100000"},
               "prices_usd": {"ETH": "3500", "USDC": "1"},
               "tokens": {"0x3333333333333333333333333333333333333333": {"symbol": "USDC", "decimals": 6}}}, open(world, "w"))
    with open(os.open(wallet, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + KEY0 + "\n")
    sb = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-wallet", wallet, "-state-dir", os.path.join(tmp, "state")],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = sb.stdout.readline()
        if "listening on" not in line:
            raise RuntimeError(f"stopbard did not start: {line!r} {sb.stderr.read()}")
        url = "http://" + line.rsplit(" ", 1)[1].strip()
        rpc = f"http://127.0.0.1:{port}"
        w3 = Web3(Web3.HTTPProvider(rpc))
        for _ in range(50):
            if w3.is_connected():
                break
            time.sleep(0.1)

        labels = ["trusted_user"]
        wp = StopbarWalletProvider(stopbard_url=url, rpc_url=rpc, address=ADDR0, chain_id=31337, provenance=lambda: labels)
        kit = AgentKit(AgentKitConfig(wallet_provider=wp, action_providers=[wallet_action_provider()]))
        transfer = next(a for a in kit.get_actions() if a.name.endswith("native_transfer"))

        # 1. A normal payment through AgentKit's own action: allowed, signed by stopbard, mined.
        before = w3.eth.get_balance(ADDR1)
        out = transfer.invoke({"to": ADDR1, "value": "0.01"})
        tx_hash = out.rsplit(" ", 1)[-1].strip()
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10) if tx_hash.startswith("0x") else {}
        after = w3.eth.get_balance(ADDR1)
        check("agentkit native_transfer to a known address is allowed and mined",
              receipt.get("status") == 1 and after - before == Web3.to_wei("0.01", "ether"),
              f"receipt status {receipt.get('status')}, received {after - before} wei")

        # 2. Half the balance: escalated (HTTP 202), nothing broadcast.
        nonce = w3.eth.get_transaction_count(ADDR0)
        out = transfer.invoke({"to": ADDR1, "value": "5000"})
        check("transfer of 50% of balance escalates, nothing sent", w3.eth.get_transaction_count(ADDR0) == nonce and wp.decisions[-1]["status"] == 202, out[:90])

        # 3. Untrusted content in context, unknown destination: denied.
        labels[:] = ["untrusted_onchain"]
        out = transfer.invoke({"to": STRANGER, "value": "0.01"})
        d = wp.decisions[-1]
        check("tainted transfer to an unknown address is denied", d["status"] == 403 and "taint-unknown-destination" in json.dumps(d["decision"]), out[:90])
        labels[:] = ["trusted_user"]

        # 4. Unlimited approval (raw call through the provider): denied before anything is signed.
        approve = "0x095ea7b3" + "0" * 24 + STRANGER[2:] + "f" * 64
        try:
            wp.send_transaction({"to": Web3.to_checksum_address("0x3333333333333333333333333333333333333333"), "data": approve})
            check("unlimited approval is denied", False, "it was sent")
        except StopbarBlocked as e:
            check("unlimited approval is denied", e.status == 403 and "unlimited-approval" in str(e), str(e))

        # 5. Off-chain signing is refused (not gated by Stopbar yet).
        try:
            wp.sign_typed_data({"types": {}, "primaryType": "Permit", "domain": {}, "message": {}})
            check("off-chain typed-data signing is refused", False)
        except StopbarBlocked as e:
            check("off-chain typed-data signing is refused", "OFFCHAIN_SIGNING_NOT_GATED" in str(e))

        # 6. The provider never held a key: the only signatures came from stopbard.
        check("provider holds no key", not any(hasattr(wp, k) for k in ("account", "private_key", "_account")))
    finally:
        sb.terminate()
        anvil.terminate()
        sb.wait(timeout=10)
        anvil.wait(timeout=10)
    print("WALLET E2E OK" if not fails else f"WALLET E2E FAILED: {fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
