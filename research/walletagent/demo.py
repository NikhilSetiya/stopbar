"""`make demo` — a product walking skeleton for Stopbar.

Fresh clone -> build -> start stopbard **from a config file** -> an AgentKit
agent runs a scripted journey on an Anvil fork of Base -> restart stopbard ->
audit verify. It is deliberately thin: its job is to walk the real path end to
end and surface the gaps (labelled below), not to hide them.

Everything here is DEV MODE on a fork with DEV KEYS and STUB price/balance data.
No real funds, no auth. Gaps and "hidden knowledge" steps are collected and
printed at the end, and the journey is timed against the PRD's 30-minute goal.
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request
import urllib.error
from decimal import Decimal

from web3 import Web3

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from harness import chain, run, world  # noqa: E402
from stopbar_wallet import StopbarBlocked, StopbarWalletProvider  # noqa: E402

REPO = HERE.parents[1]
ALICE = "0x000000000000000000000000000000000000a11c"
BOB = "0x000000000000000000000000000000000000b0b0"
UNKNOWN = "0x00000000000000000000000000000000deadbeef"  # NOT on the allowlist
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
ROUTER = "0x6ff5693b99212da76ad316178a184ab56d299b43"
MAX_UINT = (1 << 256) - 1

GAPS: list[str] = []       # product gaps the walk exposed
HIDDEN: list[str] = []     # steps that needed knowledge not in any doc/CLI


def gap(s): GAPS.append(s)
def hidden(s): HIDDEN.append(s)
def say(s=""): print(s, flush=True)
def hdr(s): say("\n" + "=" * 72 + f"\n{s}\n" + "=" * 72)


def write_decision_key(cli: pathlib.Path, path: pathlib.Path):
    # Persistent decision key (needed for audit-verify across a restart), via
    # `stopbar keygen decision-key` — no hand-writing of key-file formats.
    subprocess.run([str(cli), "keygen", "decision-key", str(path)], check=True, capture_output=True)


def demo_world(path: pathlib.Path):
    # DEV world for the stub price/balance enricher, plus one velocity cap so a
    # restart can show the cap persisting. `balances` here is STUB data, not the
    # chain: the enricher reads it, so pct-of-balance uses 10 ETH regardless of
    # the fork balance.
    path.write_text(json.dumps({
        "balances": {"ETH": "10", "USDC": "5000", "WETH": "2", "cbBTC": "0.05"},
        "prices_usd": {"ETH": "3500", "USDC": "1", "WETH": "3500", "cbBTC": "95000"},
        "known_destinations": [ALICE, BOB, ROUTER, "0x2626664c2603336e57b271c5c0b26f421741e481"],
        "tokens": {USDC: {"decimals": 6, "symbol": "USDC"},
                   "0x4200000000000000000000000000000000000006": {"decimals": 18, "symbol": "WETH"},
                   "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": {"decimals": 8, "symbol": "cbBTC"}},
        "limits": [{"scope": "wallet", "window": "24h", "max_count": 1}],
    }, indent=2))
    hidden("The DEV world file is the price/balance/allowlist STUB (internal/devstub) — real prices, "
           "balances and a destination registry are CS-131/132/133; the demo hard-codes them.")


def start_stopbard(bin_path, config, log_path):
    sb = subprocess.Popen([str(bin_path), "-config", str(config)],
                          stdout=open(log_path, "w"), stderr=subprocess.STDOUT, text=True)
    # Wait for the listener line in the log.
    for _ in range(100):
        time.sleep(0.1)
        txt = pathlib.Path(log_path).read_text()
        if "listening on" in txt:
            addr = next(l for l in txt.splitlines() if "listening on" in l).rsplit(" ", 1)[1].strip()
            return sb, "http://" + addr
    raise SystemExit(f"stopbard did not start; log:\n{pathlib.Path(log_path).read_text()}")


def post_evaluate(url, body, authz=None):
    headers = {"Content-Type": "application/json"}
    if authz:
        headers["Authorization"] = authz
    req = urllib.request.Request(url + "/v1/evaluate", data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def gen_api_key(cli, store_path, tenant, agent, scopes):
    # `stopbar keygen api-key`: secret on stderr (shown once), record on stdout.
    r = subprocess.run([str(cli), "keygen", "api-key", "--tenant", tenant, "--agent", agent, "--scopes", scopes],
                       capture_output=True, text=True, check=True)
    record = json.loads("\n".join(l for l in r.stdout.splitlines() if not l.lstrip().startswith("#")))
    secret = next(l.strip() for l in r.stderr.splitlines() if l.strip().startswith("stopbar_sk_"))
    store = json.loads(store_path.read_text()) if store_path.exists() else []  # append: a store can hold many keys
    store.append(record)
    store_path.write_text(json.dumps(store, indent=2))  # the server-side hashed store
    return secret


def reasons(d):
    return [r.get("policy_id") or r.get("code") for r in d.get("reasons", [])] or ([d.get("code")] if d.get("code") else [])


def fixed_nonce_body(wallet):
    # A tainted transfer to an unknown address with a FIXED nonce, so the demo
    # can replay it after a restart to prove the spent-nonce set persisted.
    return {"id": "req_demo_replay", "tenant": "demo", "nonce": "demo-fixed-nonce-aaaaaaaaaaaa",
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ttl_seconds": 300,
            "actor": {"agent_id": "wallet-agent"},  # must match the api key's identity
            "action": {"kind": "evm_tx", "chain_id": 8453, "from": wallet.lower(), "to": UNKNOWN,
                       "value_wei": "1000000000000000", "data": "0x", "tx_type": 2, "tx_nonce": "0",
                       "gas_limit": "21000", "max_fee_per_gas": "200000000", "max_priority_fee_per_gas": "100000000"},
            "provenance": {"labels": ["trusted_user", "untrusted_onchain"]}}


def main():
    t0 = time.time()
    hdr("Stopbar demo — DEV MODE, fork of Base, DEV KEYS, STUB price/balance data. Not for real funds.")

    binsb, binscli = REPO / "bin" / "stopbard", REPO / "bin" / "stopbar"
    if not binsb.exists() or not binscli.exists():
        raise SystemExit("build first: `make build` (expected bin/stopbard and bin/stopbar)")

    out = HERE / "results" / "demo"
    import shutil
    shutil.rmtree(out, ignore_errors=True)  # fresh keys/state each run (keygen refuses to overwrite)
    out.mkdir(parents=True, exist_ok=True)
    dec_key, wallet_file = out / "decision.key", out / "wallet.key"
    worldf, config, statedir = out / "world.json", out / "config.json", out / "state"
    keys_store = out / "api-keys.json"
    write_decision_key(binscli, dec_key)
    api_secret = gen_api_key(binscli, keys_store, "demo", "wallet-agent", "evaluate")
    with open(os.open(wallet_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + run.PILOT_KEY[2:] + "\n")
    demo_world(worldf)

    say("\nFork Base (Anvil) …")
    proc, w3, rpc = world.fork()
    sb = None
    try:
        port = run._free_port()
        config.write_text(json.dumps({
            "listen": f"127.0.0.1:{port}", "policies": str(HERE / "policies" / "pilot2"),
            "state_dir": str(statedir), "dev_world": str(worldf), "dev_wallet": str(wallet_file),
            "decision_key": str(dec_key), "tenant": "demo", "audit_checkpoint_every": 1,
            "auth_keys": str(keys_store), "rate_per_min": 600,
        }, indent=2))
        say(f"Config written: {config}")
        say("  AUTH ON: identity comes from the API key (hashed store), never the body.")
        say("  (NOTE: the config still selects DEV components — dev_world, dev_wallet, decision_key — "
            "a production config needs a real (KMS/HSM) key provider and real enrichers.)")
        gap("stopbard -config still selects dev components; a production config needs a real "
            "(KMS/HSM) key provider and real enrichers (CS-131/132/133).")

        sb, url = start_stopbard(binsb, config, out / "stopbard.log")
        say(f"stopbard up at {url} from the config file (no dev flags on the command line).")

        a0 = run.a0_provider(rpc)  # funds the wallet with the signer's own key
        run.fund(w3, a0)
        labels = ["trusted_user"]
        prov = StopbarWalletProvider(stopbard_url=url, rpc_url=rpc, address=run.WALLET, chain_id=8453,
                                     tenant="demo", api_key=api_secret, provenance=lambda: list(labels))

        # ---- Step 1: allowed contact payment (broadcast + balance change) ----
        hdr("STEP 1  Allowed contact payment  →  expect ALLOW, broadcast, balance change")
        before = w3.eth.get_balance(Web3.to_checksum_address(ALICE))
        labels[:] = ["trusted_user"]
        txh = prov.native_transfer(ALICE, Decimal("0.01"))
        after = w3.eth.get_balance(Web3.to_checksum_address(ALICE))
        say(f"  200 ALLOW — stopbard signed, agent broadcast {txh}")
        say(f"  Alice balance {before} → {after}  (+{after - before} wei)  [REAL on-chain change]")
        assert after > before, "balance did not change"

        # ---- Step 2: tainted transfer to an unknown address (deny) ----
        hdr("STEP 2  Tainted transfer to an unknown address  →  expect DENY")
        labels[:] = ["trusted_user", "untrusted_onchain"]
        try:
            prov.native_transfer(UNKNOWN, Decimal("0.5"))
            say("  !! not blocked"); gap("Step 2 (tainted transfer) was not denied.")
        except StopbarBlocked as e:
            say(f"  {e.status} DENY — {reasons(e.decision)}")

        # ---- Step 3: large share of balance (escalate) ----
        hdr("STEP 3  Transfer > 20% of balance to a contact  →  expect ESCALATE")
        labels[:] = ["trusted_user"]
        try:
            prov.native_transfer(BOB, Decimal("5"))  # 5 of 10 ETH (stub balance)
            say("  !! not escalated"); gap("Step 3 (large share) was allowed outright.")
        except StopbarBlocked as e:
            say(f"  {e.status} ESCALATE — {reasons(e.decision)}")

        # ---- Step 4: unlimited approval (deny) ----
        hdr("STEP 4  Unlimited token approval  →  expect DENY")
        labels[:] = ["trusted_user"]
        try:
            prov.send_transaction({"to": Web3.to_checksum_address(USDC), "data": chain.erc20_approve(ROUTER, MAX_UINT)})
            say("  !! not blocked"); gap("Step 4 (unlimited approval) was not denied.")
        except StopbarBlocked as e:
            say(f"  {e.status} DENY — {reasons(e.decision)}")

        # ---- Step 5: a request with no credential is rejected before anything ----
        hdr("STEP 5  Unauthenticated request (no API key)  →  expect 401")
        st, d = post_evaluate(url, fixed_nonce_body(run.WALLET), authz=None)
        say(f"  {st} {reasons(d)}  " + ("[rejected at the door, no nonce spent]" if st == 401 else "[!! not rejected]"))
        if st != 401:
            gap("Step 5 (unauthenticated request) was not rejected with 401.")

        # consume a fixed nonce now (authenticated), to replay after the restart
        st, _ = post_evaluate(url, fixed_nonce_body(run.WALLET), authz="Bearer " + api_secret)
        say(f"  (pre-restart: consumed a fixed-nonce authenticated request, status {st})")

        # ---- Step 6: restart stopbard; caps and nonces persist ----
        hdr("STEP 6  Restart stopbard (same config/state-dir/key)  →  caps & nonces persist")
        sb.terminate(); sb.wait(timeout=10)
        say("  stopbard stopped. Restarting from the same config …")
        sb, url = start_stopbard(binsb, config, out / "stopbard2.log")
        prov.url = url.rstrip("/")
        say(f"  stopbard back up at {url}")
        # nonce persistence: replay the fixed-nonce request (authenticated)
        st, d = post_evaluate(url, fixed_nonce_body(run.WALLET), authz="Bearer " + api_secret)
        say(f"  Replay the pre-restart nonce → {st} {reasons(d)}  "
            + ("[nonce set PERSISTED]" if "NONCE_REPLAYED" in reasons(d) else "[!! nonce not remembered]"))
        if "NONCE_REPLAYED" not in reasons(d):
            gap("Nonce replay set did not persist across restart.")
        # cap persistence: a second allowed payment must hit the per-wallet 24h cap
        labels[:] = ["trusted_user"]
        try:
            prov.native_transfer(BOB, Decimal("0.01"))
            say("  Second payment ALLOWED — the per-wallet cap did NOT persist across restart.")
            gap("Per-wallet velocity cap (committed count) did not persist across restart.")
        except StopbarBlocked as e:
            say(f"  Second payment {e.status} DENY — {reasons(e.decision)}  [cap count PERSISTED]")

        # ---- Step 7: one-shot audit verify (offline, over the whole log) ----
        hdr("STEP 7  Audit verify (one-shot, offline, over the whole log incl. the restart)")
        sb.terminate(); sb.wait(timeout=10); sb = None  # final checkpoint on shutdown
        v = subprocess.run([str(binscli), "audit", "verify", "--state-dir", str(statedir),
                            "--decision-key", str(dec_key), "--require-covered"], capture_output=True, text=True)
        say("  $ stopbar audit verify --state-dir … --decision-key … --require-covered")
        say("  " + (v.stdout.strip() or v.stderr.strip()))
        if v.returncode != 0:
            gap("audit verify failed: " + (v.stderr.strip()[:200]))
    finally:
        if sb:
            sb.terminate(); sb.wait(timeout=10)
        proc.terminate(); proc.wait(timeout=10)

    # ---- summary ----
    mins = (time.time() - t0) / 60
    hdr("DEMO COMPLETE")
    say(f"Wall-clock for the journey (excludes first clone/toolchain fetch): {mins:.1f} min "
        f"(PRD goal: < 30 min). Build + Foundry install are measured by `make demo` around this script.")
    say(f"\nSTUBS / DEV in play: devstub price+balance+allowlist (world.json), dev decision key, dev wallet key, "
        f"a demo API key. AUTH is ON (API key); mTLS/SPIFFE and real enrichers are the remaining work.")
    say(f"\nHIDDEN-KNOWLEDGE STEPS ({len(HIDDEN)}):")
    for h in HIDDEN:
        say(f"  - {h}")
    say(f"\nGAPS EXPOSED ({len(GAPS)}):")
    for g in GAPS:
        say(f"  - {g}")
    say("")
    return 1 if any("failed" in g or "not denied" in g or "not remembered" in g for g in GAPS) else 0


if __name__ == "__main__":
    sys.exit(main())
