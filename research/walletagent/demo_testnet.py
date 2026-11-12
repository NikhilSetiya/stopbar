"""make demo-testnet — Stopbar gatekeeper + chain enricher on LIVE Base Sepolia.

Unlike `make demo-live`, this is SCRIPTED (no model, no Together spend) and runs
against a real public testnet, not an Anvil fork. It proves the part that holds
whatever the requester is: the deterministic controls (allowlist, large-share,
unlimited-approval deny) and the chain enricher reading balances and the live
Chainlink ETH/USD feed over a real RPC.

The wallet key is generated once and kept locally (gitignored, never committed).
The FIRST run prints the wallet address and the faucet step and stops; fund that
address with a little Base Sepolia test ETH, then run again to execute the
journey. Testnet funds are worthless and nothing here uses real money.
"""
import json
import os
import pathlib
import subprocess
import sys

from eth_account import Account
from web3 import Web3

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from harness import chain, run  # noqa: E402
from demo import gen_api_key, hdr, post_evaluate, reasons, say, start_stopbard, write_decision_key  # noqa: E402

REPO = HERE.parents[1]
RPC = os.environ.get("STOPBAR_SEPOLIA_RPC", "https://sepolia.base.org")
CHAIN_ID = 84532  # Base Sepolia

# Verified on-chain against the public RPC: description() == "ETH / USD",
# decimals() == 8, chainId 84532. Do not change without re-verifying.
ETH_USD_FEED = "0x4aDC67696bA383F43DD60A9e78F2C97FbbFc7cb1"
# Conservative testnet staleness bound: mainnet ETH/USD updates ~hourly, but
# testnet feeds update irregularly, so a 24h bound keeps the demo pricing across
# gaps. A genuinely stale feed still escalates (stale-price), never a $0 guess.
ETH_HEARTBEAT = 86400

USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # Circle test USDC on Base Sepolia (T3 unlimited-approval deny)
ROUTER = "0x6ff5693b99212da76ad316178a184ab56d299b43"
BOB = "0x000000000000000000000000000000000000b0b0"       # an allowlisted sink
SUPPLIER = "0x7c9e8a2b4d6f1030a5b8c2e4f6a1b3d5e7f90c2a"  # a real-looking address NOT on the allowlist
KEYFILE = HERE / "results" / "testnet-wallet.key"        # persisted across runs, gitignored
FAUCET = ("Base Sepolia faucet: https://portal.cdp.coinbase.com/products/faucet "
          "(or https://www.alchemy.com/faucets/base-sepolia) — needs your login/captcha.")

SEL_LATEST_ROUND = "0xfeaf968c"  # latestRoundData()


def load_or_create_wallet():
    """Return (priv_hex_no_0x, checksum_address), generating a fresh key on the
    first run. The key lives only in KEYFILE (mode 0600) and is never committed."""
    KEYFILE.parent.mkdir(parents=True, exist_ok=True)
    if KEYFILE.exists():
        priv = KEYFILE.read_text().strip().splitlines()[-1]
    else:
        priv = Account.create().key.hex()
        priv = priv[2:] if priv.startswith("0x") else priv
        with open(os.open(KEYFILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as f:
            f.write("stopbar-dev-wallet-secp256k1-v1\n" + priv + "\n")
    return priv, Account.from_key(priv).address


def eth_usd(w3):
    """Read the same Chainlink ETH/USD feed stopbard uses, so the live price is
    visible in the demo output."""
    ret = w3.eth.call({"to": Web3.to_checksum_address(ETH_USD_FEED), "data": SEL_LATEST_ROUND})
    answer = int.from_bytes(ret[32:64], "big", signed=True)
    return answer / 1e8


def testnet_world(path):
    path.write_text(json.dumps({
        "chain_rpc": RPC,
        "feeds": {"native": {"address": ETH_USD_FEED, "max_age_sec": ETH_HEARTBEAT}},
        "known_destinations": [BOB, ROUTER],
        "limits": [{"scope": "wallet", "window": "1h", "max_usd": "50000", "max_count": 50}],
    }, indent=2))


def tx_body(idn, frm, to, value_wei, data, nonce, chain_id=CHAIN_ID):
    return {
        "id": idn, "tenant": "demo", "nonce": "testnet-" + idn,
        "issued_at": run.now(), "ttl_seconds": 120,
        "actor": {"agent_id": "wallet-agent"},
        "action": {"kind": "evm_tx", "chain_id": chain_id, "from": frm.lower(), "to": to.lower(),
                   "value_wei": str(value_wei), "data": data, "tx_type": 2, "tx_nonce": str(nonce),
                   "gas_limit": "21000" if data == "0x" else "120000",
                   "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000"},
        "provenance": {"labels": ["trusted_user"]},
    }


def main():
    binsb, binscli = REPO / "bin" / "stopbard", REPO / "bin" / "stopbar"
    if not binsb.exists() or not binscli.exists():
        raise SystemExit("build first: bin/stopbard and bin/stopbar")

    priv, addr = load_or_create_wallet()
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise SystemExit(f"cannot reach Base Sepolia RPC {RPC}")
    if w3.eth.chain_id != CHAIN_ID:
        raise SystemExit(f"RPC {RPC} is chain {w3.eth.chain_id}, expected Base Sepolia {CHAIN_ID}")
    bal = w3.eth.get_balance(addr)

    hdr("make demo-testnet — Stopbar gatekeeper + chain enricher on LIVE Base Sepolia")
    say(f"wallet:  {addr}")
    say(f"key:     {KEYFILE.relative_to(REPO)}  (mode 0600, gitignored, never committed)")
    say(f"rpc:     {RPC}  (chain {CHAIN_ID})")
    say(f"balance: {bal / 1e18:.6f} test ETH")
    if bal == 0:
        say("\n>>> FUND THIS ADDRESS, then run `make demo-testnet` again:")
        say(f"      {addr}")
        say(f"      {FAUCET}")
        say("      ~0.02 test ETH is plenty (worthless testnet funds).")
        return 0

    price = eth_usd(w3)
    say(f"ETH/USD: ${price:,.2f}  (read live from Chainlink {ETH_USD_FEED} — the same feed stopbard prices with)\n")

    out = HERE / "results" / "demo-testnet"
    import shutil
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    dec_key, wallet_file = out / "decision.key", out / "wallet.key"
    worldf, config, statedir, keys_store = out / "world.json", out / "config.json", out / "state", out / "api-keys.json"
    write_decision_key(binscli, dec_key)
    api_secret = gen_api_key(binscli, keys_store, "demo", "wallet-agent", "evaluate")
    approve_secret = gen_api_key(binscli, keys_store, "demo", "operator", "approve")
    with open(os.open(wallet_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + priv + "\n")
    testnet_world(worldf)

    sb = None
    try:
        port = run._free_port()
        config.write_text(json.dumps({
            "listen": f"127.0.0.1:{port}", "policies": str(HERE / "policies" / "demo"),
            "state_dir": str(statedir), "dev_world": str(worldf), "dev_wallet": str(wallet_file),
            "decision_key": str(dec_key), "tenant": "demo", "audit_checkpoint_every": 1,
            "auth_keys": str(keys_store), "rate_per_min": 600,
        }, indent=2))
        sb, url = start_stopbard(binsb, config, out / "stopbard.log")
        say(f"stopbard up at {url} (gatekeeper, allowlist policy, auth on, chain enricher → Base Sepolia)\n")

        nonce = w3.eth.get_transaction_count(addr)
        authz = "Bearer " + api_secret
        outcomes = []

        # 1) ALLOW — a small transfer to an allowlisted address, broadcast live.
        hdr("1) pay an allowlisted address 0.0002 ETH")
        small = Web3.to_wei("0.0002", "ether")
        st, d = post_evaluate(url, tx_body("req_tn_allow", addr, BOB, small, "0x", nonce), authz=authz)
        if st == 200 and d.get("signed_tx"):
            txh = w3.eth.send_raw_transaction(d["signed_tx"])
            w3.eth.wait_for_transaction_receipt(txh, timeout=60)
            say(f"  ⟵ STOPBAR: ALLOWED — stopbard signed, broadcast {Web3.to_hex(txh)}")
            nonce += 1
            outcomes.append("ALLOWED (broadcast)")
        else:
            say(f"  ⟵ STOPBAR: HTTP {st} {reasons(d)} (expected 200 allow)")
            outcomes.append(f"HTTP {st}")

        # 2) ESCALATE — a large share of the real on-chain balance, then approve.
        hdr("2) send a large share of the balance to an allowlisted address")
        big = int(bal * 0.6)  # > 20% of the REAL chain balance → large-share escalate
        st, d = post_evaluate(url, tx_body("req_tn_escalate", addr, BOB, big, "0x", nonce), authz=authz)
        say(f"  ⟵ STOPBAR: HTTP {st} {reasons(d)}  (large share of a REAL {bal / 1e18:.5f} ETH balance)")
        if st == 202:
            esc_id = d["request_id"]
            say(f"  escalated id: {esc_id} — operator runs `stopbar approve` (re-reads chain balance + price)")
            r = subprocess.run([str(binscli), "approve", esc_id, "--url", url, "--key", approve_secret],
                               capture_output=True, text=True)
            body = r.stdout.split("\n", 1)[1] if "\n" in r.stdout else "{}"
            try:
                ad = json.loads(body)
            except ValueError:
                ad = {}
            if ad.get("signed_tx"):
                say("  ⟵ STOPBAR: approved — re-evaluated against current chain state, signed, payload bound")
                say(f"           (not broadcast, to keep the testnet balance; set BROADCAST_APPROVE=1 to send)")
                if os.environ.get("BROADCAST_APPROVE") == "1":
                    txh = w3.eth.send_raw_transaction(ad["signed_tx"])
                    w3.eth.wait_for_transaction_receipt(txh, timeout=60)
                    say(f"  ⟵ STOPBAR: broadcast {Web3.to_hex(txh)}")
                outcomes.append("ESCALATED → APPROVED (re-evaluated, signed)")
            else:
                outcomes.append(f"ESCALATED → refused on approval ({reasons(ad)})")
        else:
            outcomes.append(f"HTTP {st} (expected 202 escalate)")

        # 3) DENY — a transfer to an address that is not on the allowlist.
        hdr("3) pay an unknown (non-allowlisted) supplier")
        st, d = post_evaluate(url, tx_body("req_tn_unknown", addr, SUPPLIER, small, "0x", nonce), authz=authz)
        say(f"  ⟵ STOPBAR: HTTP {st} {reasons(d)}  " + ("[DENIED]" if st == 403 else "[!! not denied]"))
        outcomes.append("DENIED (unknown-destination)" if st == 403 else f"HTTP {st}")

        # 4) DENY (T3) — a compromised but authenticated service asks for an unlimited approval.
        hdr("4) compromised requester (T3): unlimited USDC approval to the router")
        st, d = post_evaluate(url, tx_body("req_tn_t3", addr, USDC, 0, chain.erc20_approve(ROUTER, (1 << 256) - 1), nonce), authz=authz)
        say(f"  ⟵ STOPBAR: HTTP {st} {reasons(d)}  " + ("[DENIED — forbidden whoever asks]" if st == 403 else "[!! not denied]"))
        outcomes.append("DENIED (unlimited-approval)" if st == 403 else f"HTTP {st}")

        hdr("DONE — outcomes on LIVE Base Sepolia (scripted; the deterministic controls)")
        for p, oc in zip(["pay allowlisted 0.0002 ETH", "send a large share (escalate → approve)",
                          "pay unknown supplier", "unlimited approval (T3)"], outcomes):
            say(f"  {p:42s} → {oc}")
        say("\nNo model and no real money: this is the part of Stopbar that holds whatever the requester is. "
            "Prices and balances came from the chain over a real RPC; the allow was signed by stopbard and "
            "broadcast on Base Sepolia.")
    finally:
        if sb:
            sb.terminate()
            sb.wait(timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
