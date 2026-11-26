"""`stopbar init` to a protected agent through live binaries (CS-195;
scripts/e2e.sh, CI).

Usage: e2e_init.py PATH/TO/stopbard PATH/TO/stopbar
In a temp dir: `stopbar init` writes the tree; a second init is refused, and
--force regenerates it. stopbard starts from the generated config alone (only
-listen is overridden, to a free loopback port) and must come up with auth on
and the approvers loaded. Then: an unauthenticated evaluate is refused (401);
0.01 ETH from the generated gatekeeper wallet is allowed and signed; 0.5 ETH
(50% of the balance) escalates; the first generated approver key leaves it
pending (HTTP 202) and the second reaches the 2-of-2 quorum and returns the
signed tx. After shutdown `stopbar audit verify --require-covered` passes
with the generated decision key, and init --force refuses to run over the
state that now holds the audit log. Each step is timed. Stdlib only.
"""
import datetime, json, os, re, secrets, subprocess, sys, tempfile, time, urllib.error, urllib.request

stopbard, cli = sys.argv[1], sys.argv[2]
BOB = "0x000000000000000000000000000000000000b0b0"
t0 = last = time.monotonic()


def expect(cond, msg):
    global last
    if not cond:
        sys.exit(f"FAIL init e2e: {msg}")
    now = time.monotonic()
    print(f"ok   [{now - last:5.2f}s] {msg}")
    last = now


def init(d, *extra):
    return subprocess.run([cli, "init", "--dir", d, *extra], capture_output=True, text=True)


def evaluate(url, key, wallet, value_wei, tx_nonce):
    body = {"id": "req_" + secrets.token_hex(8), "tenant": "demo", "nonce": secrets.token_urlsafe(16),
            "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ttl_seconds": 60,
            "actor": {"agent_id": "wallet-agent"},
            "action": {"kind": "evm_tx", "chain_id": 8453, "from": wallet, "to": BOB, "value_wei": value_wei, "data": "0x",
                       "tx_type": 2, "tx_nonce": tx_nonce, "gas_limit": "21000", "max_fee_per_gas": "200000000",
                       "max_priority_fee_per_gas": "100000000"},
            "provenance": {"labels": ["trusted_user"]}}
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(url + "/v1/evaluate", data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


with tempfile.TemporaryDirectory() as tmp:
    d = os.path.join(tmp, "stopbar")
    r = init(d)
    expect(r.returncode == 0, "stopbar init --persona agent-wallet (default) writes the tree")
    r2 = init(d)
    expect(r2.returncode != 0 and "refusing to overwrite" in r2.stderr, "a second init is refused without --force")
    r = init(d, "--force")
    expect(r.returncode == 0, "init --force regenerates it")
    secret = re.search(r"stopbar_sk_[A-Za-z0-9_-]+", r.stdout).group(0)
    wallet = re.search(r"gatekeeper wallet (0x[0-9a-fA-F]{40})", r.stdout).group(1)
    expect(not any(secret in open(os.path.join(dp, f), errors="ignore").read() for dp, _, fs in os.walk(d) for f in fs),
           "the API key secret is printed once and written nowhere")
    cfg = json.load(open(os.path.join(d, "stopbard.json")))
    expect(cfg["listen"].startswith("127.0.0.1:") and cfg["auth_keys"] and cfg["approvers"] and cfg["approval_quorum"] == 2,
           f"config is secure by default: listen {cfg['listen']}, auth on, approvers, quorum {cfg['approval_quorum']}")
    secret_files = ["stopbard.json", "world.json", "decision.key", "wallet.key", "api-keys.json", "approvers.json", "approver-1.key", "approver-2.key"]
    expect(all(os.stat(os.path.join(d, f)).st_mode & 0o077 == 0 for f in secret_files), "generated files are mode 0600")

    proc = subprocess.Popen([stopbard, "-config", os.path.join(d, "stopbard.json"), "-listen", "127.0.0.1:0"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        if "listening on" not in line:
            sys.exit(f"stopbard did not start: {line!r} {proc.stderr.read()}")
        url = "http://" + line.rsplit(" ", 1)[1].strip()
        expect(True, f"stopbard -config starts from the generated config ({url})")

        st, _ = evaluate(url, None, wallet, "10000000000000000", "0")
        expect(st == 401, f"evaluate without the API key: HTTP {st} (auth is on)")
        st, dd = evaluate(url, secret, wallet, "10000000000000000", "0")
        expect(st == 200 and dd.get("outcome") == "allow" and dd.get("signed_tx"), f"0.01 ETH to Bob: HTTP {st} allow, signed by the gatekeeper wallet")
        st, dd = evaluate(url, secret, wallet, "500000000000000000", "1")
        rid = dd.get("request_id", "")
        pids = [x.get("policy_id") for x in dd.get("reasons", [])]
        expect(st == 202 and "large-share-of-balance" in pids and rid, f"0.5 ETH (50% of balance) escalates: HTTP {st} {pids}")
        approve = lambda n: subprocess.run([cli, "approve", rid, "--approver-key", os.path.join(d, f"approver-{n}.key"), "--url", url, "--key", secret, "--yes"],
                                           capture_output=True, text=True)  # --yes: no terminal to confirm at (CS-143)
        a1 = approve(1)
        expect(a1.returncode != 0 and "HTTP 202" in a1.stdout, "approver-1 signs: 1 of 2, still pending (HTTP 202)")
        a2 = approve(2)
        out = json.loads(a2.stdout.split("\n", 1)[1]) if a2.returncode == 0 else {}
        expect(a2.returncode == 0 and out.get("outcome") == "allow" and out.get("signed_tx"),
               "approver-2 signs: 2-of-2 quorum, re-evaluated, allowed with the signed tx")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    expect(proc.returncode == 0, "stopbard shuts down cleanly (final checkpoint signed)")

    v = subprocess.run([cli, "audit", "verify", "--state-dir", os.path.join(d, "state"), "--decision-key", os.path.join(d, "decision.key"),
                        "--require-covered"], capture_output=True, text=True)
    expect(v.returncode == 0, "audit verify --require-covered: " + (v.stdout or v.stderr).strip())
    r = init(d, "--force")
    expect(r.returncode != 0 and "state.db" in r.stderr, "init --force refuses to run over the state that holds the audit log")
print(f"ok   stopbar init -> protected agent in {time.monotonic() - t0:.1f}s of machine time")
