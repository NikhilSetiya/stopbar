"""Quickstart T3 (compromised requester, CS-198): an attacker holds the agent's
API key and calls /v1/evaluate directly, with no SDK, forged clean provenance
(trusted_user, no taint) and a valid request. It asks for an unlimited USDC
approval to itself from the gatekeeper wallet. Taint can't help here (the
requester lies); the decoded intent can: HTTP 403, unlimited-approval, and
nothing is signed. Exits non-zero otherwise. Stdlib only.

Env: STOPBAR_URL, STOPBAR_KEY, STOPBAR_TENANT, STOPBAR_WALLET.
"""
import datetime, json, os, secrets, sys, urllib.error, urllib.request

ATTACKER = "9f30000000000000000000000000000000000c21"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
body = {
    "id": "req_" + secrets.token_hex(8), "tenant": os.environ.get("STOPBAR_TENANT", "demo"), "nonce": secrets.token_urlsafe(16),
    "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ttl_seconds": 60,
    "actor": {"agent_id": "wallet-agent"},
    "action": {"kind": "evm_tx", "chain_id": 8453, "from": os.environ["STOPBAR_WALLET"].lower(), "to": USDC, "value_wei": "0",
               "data": "0x095ea7b3" + ATTACKER.rjust(64, "0") + "f" * 64,  # approve(attacker, 2^256-1)
               "tx_type": 2, "tx_nonce": "0", "gas_limit": "100000", "max_fee_per_gas": "2000000000",
               "max_priority_fee_per_gas": "1000000000"},
    "provenance": {"labels": ["trusted_user"]},  # forged: the requester claims a clean context
}
req = urllib.request.Request(os.environ["STOPBAR_URL"] + "/v1/evaluate", json.dumps(body).encode(), method="POST",
                             headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["STOPBAR_KEY"]})
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        status, d = r.status, json.load(r)
except urllib.error.HTTPError as e:
    status, d = e.code, json.load(e)
ids = [x.get("policy_id") or x.get("code") for x in d.get("reasons", [])]
print(f"T3 compromised requester, unlimited USDC approval to the attacker: HTTP {status} {d.get('outcome')} {ids}"
      f"{', signed tx returned' if d.get('signed_tx') else ', nothing signed'}")
sys.exit(0 if status == 403 and "unlimited-approval" in ids and not d.get("signed_tx") else 1)
