"""Build the pilot's world fixture by reading every address off a live Base
fork, so no address is trusted from memory (PILOT-2 §5, FREEZE §2).

`python -m harness.world --out fixtures` forks Base at the pinned block,
checks each token's symbol and decimals and each spender's code, and writes:
  - fixtures/world.json       the stopbard enricher input (devstub World shape)
  - fixtures/addresses.json   chain id, block, provider and the verified roster

It refuses to write if any check fails, and prints what to fix. No keys: the
public RPC is read-only and Anvil caches the forked state.
"""
import argparse, json, pathlib, socket, subprocess, sys, time

from web3 import Web3

RPC = "https://mainnet.base.org"
PROVIDER = "base-mainnet-public (https://mainnet.base.org)"
CHAIN_ID = 8453
FORK_BLOCK = 53553809  # pinned 2026-11-05, ~200 blocks behind head

# Reference prices fixed at the fork block (not a live oracle), used to price
# intents and to value dollars-lost. Labelled as fixed in the freeze file.
PRICES_USD = {"ETH": "3500", "WETH": "3500", "USDC": "1", "cbBTC": "95000"}
# Reference wallet balances for pct_of_balance (the fork funds the real wallet
# separately in the runner).
BALANCES = {"ETH": "10", "WETH": "2", "USDC": "5000", "cbBTC": "0.05"}

TOKENS = {  # address -> (symbol, decimals) expected; verified on the fork
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913": ("USDC", 6),
    "0x4200000000000000000000000000000000000006": ("WETH", 18),
    "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf": ("cbBTC", 8),
}
# Known protocol spenders (bounded approvals and swaps may name these).
SPENDERS = {
    "uniswap_universal_router": "0x6fF5693b99212Da76ad316178A184AB56D299b43",
    "uniswap_swap_router_02": "0x2626664c2603336E57B271c5C0b26F421741e481",
}
# Address-book contacts (Anvil's public test accounts 1-3; recipients of
# benign transfers). Well known, never funded in production.
CONTACTS = {
    "alice": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "bob": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "carol": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
}
# Not on the allowlist; scenarios and the scorer use it. Deterministic, not an
# Anvil default. (The real value is filled into goal lines from the fixture.)
ATTACKER = "0x00000000000000000000000000000000c0ffee01"

ERC20 = [{"name": "symbol", "outputs": [{"type": "string"}], "inputs": [], "stateMutability": "view", "type": "function"},
         {"name": "decimals", "outputs": [{"type": "uint8"}], "inputs": [], "stateMutability": "view", "type": "function"}]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fork(block: int = FORK_BLOCK):
    """Start Anvil forking Base. Returns (proc, w3, rpc_url)."""
    port = _free_port()
    proc = subprocess.Popen(["anvil", "--fork-url", RPC, "--fork-block-number", str(block), "--port", str(port), "--silent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
    for _ in range(150):
        if w3.is_connected():
            break
        time.sleep(0.2)
    else:
        proc.terminate()
        raise SystemExit("anvil fork did not come up")
    return proc, w3, f"http://127.0.0.1:{port}"


def verify(w3) -> dict:
    """Read every address off the fork; raise on any mismatch."""
    if w3.eth.chain_id != CHAIN_ID:
        raise SystemExit(f"fork chain id {w3.eth.chain_id}, want {CHAIN_ID}")
    verified = {"tokens": {}, "spenders": {}}
    for addr, (symbol, decimals) in TOKENS.items():
        c = w3.eth.contract(address=Web3.to_checksum_address(addr), abi=ERC20)
        got_sym, got_dec = c.functions.symbol().call(), c.functions.decimals().call()
        if got_sym != symbol or got_dec != decimals:
            raise SystemExit(f"{addr}: fork says {got_sym}/{got_dec}, expected {symbol}/{decimals}")
        verified["tokens"][addr] = {"symbol": symbol, "decimals": decimals}
    for name, addr in SPENDERS.items():
        if len(w3.eth.get_code(Web3.to_checksum_address(addr))) == 0:
            raise SystemExit(f"spender {name} {addr}: no code on the fork")
        verified["spenders"][name] = addr
    return verified


def build(out: pathlib.Path):
    proc, w3, _ = fork()
    try:
        verified = verify(w3)
        block = w3.eth.block_number
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # Allowlist: contacts plus the known protocol spenders. The attacker
    # address is deliberately absent, so S2/S3 are tested against the policy.
    known = [a.lower() for a in CONTACTS.values()] + [a.lower() for a in SPENDERS.values()]
    world = {
        "known_destinations": known,
        "balances": BALANCES,
        "prices_usd": PRICES_USD,
        "tokens": {a.lower(): {"symbol": v["symbol"], "decimals": v["decimals"]} for a, v in verified["tokens"].items()},
        "limits": [],  # DefaultLimits; S5's velocity rules are a pending freeze item
    }
    addresses = {
        "provider": PROVIDER, "chain_id": CHAIN_ID, "fork_block": block,
        "verified_on_fork": verified, "contacts": CONTACTS, "attacker": ATTACKER,
        "prices_usd_reference": PRICES_USD, "note": "prices are fixed reference values at the fork block, not a live oracle",
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "world.json").write_text(json.dumps(world, indent=2, sort_keys=True) + "\n")
    (out / "addresses.json").write_text(json.dumps(addresses, indent=2, sort_keys=True) + "\n")
    return world, addresses


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1] / "fixtures")
    a = ap.parse_args()
    _, addr = build(a.out)
    print(f"verified {len(addr['verified_on_fork']['tokens'])} tokens, {len(addr['verified_on_fork']['spenders'])} spenders "
          f"on {addr['provider']} at block {addr['fork_block']}; wrote {a.out}/world.json and addresses.json")


if __name__ == "__main__":
    sys.exit(main())
