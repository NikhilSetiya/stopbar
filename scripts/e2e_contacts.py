"""Destination registry end to end: CLI -> state file -> live stopbard (CS-133, scripts/e2e.sh).

Usage: e2e_contacts.py PATH/TO/stopbard PATH/TO/stopbar
The world registers nothing. `stopbar contacts add` registers the payee in
the stopped server's state file; after a restart, a payment to the payee is
allowed and one to its look-alike escalates (address-poisoning). After
`contacts remove` and another restart the look-alike is just a new
destination again (allowed). The audit log, with the CLI's records, verifies.
"""
import json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
from corpus_template import Templater

stopbard, cli = sys.argv[1], sys.argv[2]
entry = yaml.safe_load(open("corpus/attacks/CS-2026-0011-address-poisoning.yaml"))
payee = entry["setup"]["known_destinations"][0]
to_payee, to_lookalike = entry["requests"]
tpl = Templater()
failures = 0


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print("ok  " if ok else "FAIL", name + (f": {detail}" if detail else ""))


def serve(world, state, keyfile):
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-state-dir", state,
                             "-decision-key", keyfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if "listening on" not in line:
        raise SystemExit(f"stopbard did not start: {line!r} {proc.stderr.read()}")
    return proc, line.rsplit(" ", 1)[1].strip()


def evaluate(addr, body, i):
    b = tpl.render(dict(body, id=f"{body['id']}_{i}", nonce=f"{body['nonce']}{i}"))
    r = urllib.request.Request(f"http://{addr}/v1/evaluate", data=json.dumps(b).encode(), method="POST",
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            status, d = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, d = e.code, json.loads(e.read())
    return status, [x.get("policy_id") or x.get("code") for x in d.get("reasons", [])]


def contacts(*args):
    return subprocess.run([cli, "contacts", *args], capture_output=True, text=True)


with tempfile.TemporaryDirectory() as tmp:
    world, state, key = (os.path.join(tmp, f) for f in ("world.json", "state", "decision.key"))
    # Several 2,500 USDC payments run here; a roomy cap keeps the limiter out of the way.
    setup = dict(entry["setup"], known_destinations=[], limits=[{"scope": "wallet", "window": "1h", "max_usd": "100000"}])
    json.dump(setup, open(world, "w"))
    subprocess.run([cli, "keygen", "decision-key", key], check=True, capture_output=True)

    proc, addr = serve(world, state, key)
    status, got = evaluate(addr, to_lookalike, 0)
    check("empty registry: look-alike is just a new destination", status == 200, f"HTTP {status} {got}")
    out = contacts("add", payee, "--state-dir", state, "--tenant", "test")
    check("contacts add refused while stopbard holds the state file", out.returncode != 0, out.stderr.strip()[:80])
    proc.terminate(); proc.wait(timeout=10)

    out = contacts("add", payee, "--state-dir", state, "--tenant", "test", "--label", "vendor", "--decision-key", key)
    check("contacts add (stopped server)", out.returncode == 0 and "added" in out.stdout, out.stdout.strip() or out.stderr.strip())
    out = contacts("list", "--state-dir", state, "--tenant", "test")
    check("contacts list shows it", payee in out.stdout, out.stdout.strip().splitlines()[-1] if out.stdout else out.stderr)

    proc, addr = serve(world, state, key)
    status, got = evaluate(addr, to_payee, 1)
    check("registered payee allowed", status == 200, f"HTTP {status} {got}")
    status, got = evaluate(addr, to_lookalike, 2)
    check("look-alike escalates", status == 202 and got == ["address-poisoning"], f"HTTP {status} {got}")
    proc.terminate(); proc.wait(timeout=10)

    out = contacts("remove", payee, "--state-dir", state, "--tenant", "test", "--decision-key", key)
    check("contacts remove", out.returncode == 0 and "removed" in out.stdout, out.stdout.strip() or out.stderr.strip())
    proc, addr = serve(world, state, key)
    status, got = evaluate(addr, to_lookalike, 3)
    check("after remove: look-alike no longer similar to anything", status == 200, f"HTTP {status} {got}")
    proc.terminate(); proc.wait(timeout=10)

    v = subprocess.run([cli, "audit", "verify", "--state-dir", state, "--decision-key", key, "--require-covered"],
                       capture_output=True, text=True)
    check("audit verify over decisions + registry changes", v.returncode == 0, (v.stdout or v.stderr).strip())
    ex = subprocess.run([cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    ops = [json.loads(l)["body"]["op"] for l in ex.stdout.splitlines() if json.loads(l)["type"] == "destination_change"]
    check("registry changes audited", ops == ["add", "remove"], str(ops))
sys.exit(failures)
