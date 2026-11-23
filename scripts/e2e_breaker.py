"""Circuit breaker trip -> M-of-N reset through live binaries (CS-124; scripts/e2e.sh, CI).

Usage: e2e_breaker.py PATH/TO/stopbard PATH/TO/stopbar
Runs corpus CS-2026-0011 against stopbard with authentication on and
-breaker-quorum 2: one evaluate key, two approver keys (`stopbar keygen`).
The breach trips the breaker (CIRCUIT_OPEN, trips_total 1); `stopbar breaker
reset` with one approver is refused (non-zero exit, a tiny transfer is still
denied CIRCUIT_OPEN); the second approver closes it and the same transfer is
allowed and signed. After shutdown the audit log must verify, covered, with
the breaker's trip, vote and reset recorded. Needs: pyyaml.
"""
import json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
from corpus_template import Templater

stopbard, cli = sys.argv[1], sys.argv[2]
ANVIL_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # public test key (e2e_corpus.py)
entry = yaml.safe_load(open("corpus/attacks/CS-2026-0011-tenant-outflow-breaker.yaml"))
steps, tpl = entry["requests"], Templater()


def keygen(store, scopes):
    r = subprocess.run([cli, "keygen", "api-key", "--tenant", "test", "--agent", "defi-agent", "--scopes", scopes],
                       capture_output=True, text=True, check=True)
    store.append(json.loads("\n".join(l for l in r.stdout.splitlines() if not l.lstrip().startswith("#"))))
    return next(l.strip() for l in r.stderr.splitlines() if l.strip().startswith("stopbar_sk_"))


def evaluate(addr, key, body):
    req = urllib.request.Request(f"http://{addr}/v1/evaluate", data=json.dumps(tpl.render(body)).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def expect(cond, msg):
    if not cond:
        sys.exit(f"FAIL breaker e2e: {msg}")
    print("ok  ", msg)


def codes(d):
    return [r.get("code") for r in d.get("reasons", [])]


with tempfile.TemporaryDirectory() as tmp:
    world, wallet, keys_file, state, jwks = (os.path.join(tmp, f) for f in ("world.json", "wallet", "api-keys.json", "state", "keys.json"))
    json.dump(entry["setup"], open(world, "w"))
    with open(os.open(wallet, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + ANVIL_KEY + "\n")
    store = []
    agent, alice, bob = keygen(store, "evaluate"), keygen(store, "approve"), keygen(store, "approve")
    json.dump(store, open(keys_file, "w"))
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-wallet", wallet, "-state-dir", state,
                             "-auth-keys", keys_file, "-breaker-quorum", "2", "-audit-checkpoint-every", "2"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        if "listening on" not in line:
            sys.exit(f"stopbard did not start: {line!r} {proc.stderr.read()}")
        addr = line.rsplit(" ", 1)[1].strip()
        url = f"http://{addr}"
        breaker = lambda *a: subprocess.run([cli, "breaker", *a, "--tenant", "test", "--url", url], capture_output=True, text=True)

        st, d = evaluate(addr, agent, steps[0])
        expect(st == 200 and d.get("signed_tx"), "step 0 (~$25k) allowed and signed")
        st, d = evaluate(addr, agent, steps[1])
        expect(st == 403 and "CIRCUIT_OPEN" in codes(d), "step 1 (tenant outflow ~$50k > $30k) trips the breaker: 403 CIRCUIT_OPEN")
        with urllib.request.urlopen(f"{url}/metrics", timeout=5) as r:
            expect("stopbar_circuit_breaker_trips_total 1" in r.read().decode(), "/metrics: stopbar_circuit_breaker_trips_total 1")
        s = breaker("status", "--key", alice)
        expect(s.returncode == 0 and "OPEN" in s.stdout, "`stopbar breaker status` reports OPEN")

        r = breaker("reset", "--key", alice)
        expect(r.returncode != 0 and "reset refused: 1 of 2" in r.stderr, "reset with 1 of 2 approver signatures refused")
        st, d = evaluate(addr, agent, steps[2])
        expect(st == 403 and "CIRCUIT_OPEN" in codes(d), "a $0.48 transfer is still denied CIRCUIT_OPEN")
        r = breaker("reset", "--key", agent)
        expect(r.returncode != 0 and "403" in r.stderr, "an evaluate-only key cannot vote")
        r = breaker("reset", "--key", bob)
        expect(r.returncode == 0 and "CLOSED" in r.stdout, "second approver completes the quorum: breaker CLOSED")
        st, d = evaluate(addr, agent, dict(steps[2], nonce="post-reset"))  # a fresh request: the denied one spent its nonce
        expect(st == 200 and d.get("signed_tx"), "after reset the $0.48 transfer is allowed and signed")
        with urllib.request.urlopen(f"{url}/metrics", timeout=5) as r:
            expect("stopbar_circuit_breaker_resets_total 1" in r.read().decode(), "/metrics: stopbar_circuit_breaker_resets_total 1")
        with urllib.request.urlopen(f"{url}/v1/keys", timeout=5) as r:
            open(jwks, "wb").write(r.read())
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    v = subprocess.run([cli, "audit", "verify", "--state-dir", state, "--keys", jwks, "--require-covered"], capture_output=True, text=True)
    expect(v.returncode == 0, "audit verify --require-covered: " + (v.stdout or v.stderr).strip())
    ex = subprocess.run([cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    events = [json.loads(l)["body"]["event"] for l in ex.stdout.splitlines() if json.loads(l)["type"] == "breaker"]
    expect(events == ["trip", "reset_vote", "reset"], f"breaker audit records {events}")
print("ok   circuit breaker: trip -> CIRCUIT_OPEN until a 2-of-N reset, alert metric, audited")
