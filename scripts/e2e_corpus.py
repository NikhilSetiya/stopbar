"""Replay every corpus attack through a live stopbard over HTTP (scripts/e2e.sh, CI).

Usage: e2e_corpus.py PATH/TO/stopbard PATH/TO/stopbar
For each corpus/attacks/*.yaml: start stopbard on the entry's `setup` (dev
stubs + the real engine, limiter and starter policy bundle) and POST its
request, or each request of its `requests` sequence in order. Requests are
templates (scripts/corpus_template.py): fresh issued_at and nonces each run,
with the rewritten bytes printed. Every step
before expected.at_step must be allowed (200). The stopping step must have
the expected outcome as its HTTP status (allow 200 / escalate 202 / deny 403 /
reject 400, refused by the gateway and never evaluated),
exactly the expected policy IDs and the expected reason code if one is
given. After shutdown, `stopbar audit verify --require-covered` must pass over
the run's own audit log, the stopping decision must be audited (a reject must
not reach the engine), and every signed tx must have a commit record. stopbard runs in gatekeeper mode: every allowed step must
return a signed tx, which `stopbar decode-tx` decodes independently. Its
recovered sender must equal `from` and its payload hash the decision's.
Needs: pyyaml.
"""
import glob, json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
from corpus_template import Templater

STATUS = {"allow": 200, "escalate": 202, "deny": 403, "reject": 400}
stopbard, stopbar_cli = sys.argv[1], sys.argv[2]
# Anvil test account 0: a public test key, never funded. Corpus `from`
# addresses use it, so gatekeeper mode can sign the allowed steps.
ANVIL_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
failures = 0


def post(addr, body):
    raw = json.dumps(body, separators=(",", ":")).encode()
    print("     sent:", raw.decode())  # the rewritten bytes, so every run is reproducible from its log
    req = urllib.request.Request(f"http://{addr}/v1/evaluate", data=raw,
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check_signed(i, sent, d):
    """An allow must carry a signed tx that does exactly what was approved."""
    if not d.get("signed_tx") or not d.get("token"):
        return [f"step {i}: allow without signed_tx/token"]
    out = subprocess.run([stopbar_cli, "decode-tx", d["signed_tx"]], capture_output=True, text=True)
    if out.returncode != 0:
        return [f"step {i}: decode-tx failed: {out.stderr.strip()}"]
    tx = json.loads(out.stdout)
    errs = []
    if tx["action"]["from"] != sent["action"]["from"].lower():
        errs.append(f"step {i}: recovered sender {tx['action']['from']} != from {sent['action']['from']}")
    if tx["payload_hash"] != d["payload_hash"]:
        errs.append(f"step {i}: signed tx payload {tx['payload_hash']} != decision {d['payload_hash']}")
    if tx["tx_hash"] != d.get("tx_hash"):
        errs.append(f"step {i}: tx_hash mismatch")
    if not errs:
        print(f"     step {i}: signed by {tx['action']['from']}, tx {tx['tx_hash'][:18]}…, payload bound")
    return errs


for path in sorted(glob.glob("corpus/attacks/*.yaml")):
    entry = yaml.safe_load(open(path))
    want = entry["expected"]
    steps = entry.get("requests") or [entry["request"]]
    stop_at = want.get("at_step", len(steps) - 1)
    problems = []
    setup = dict(entry.get("setup", {}))
    tpl = Templater(setup.pop("issued_at_offset", "0s"))
    with tempfile.TemporaryDirectory() as tmp:
        world, wallet, keys, state = (os.path.join(tmp, f) for f in ("world.json", "wallet", "keys.json", "state"))
        json.dump(setup, open(world, "w"))
        with open(os.open(wallet, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            f.write("stopbar-dev-wallet-secp256k1-v1\n" + ANVIL_KEY + "\n")
        proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-wallet", wallet,
                                 "-state-dir", state, "-audit-checkpoint-every", "2"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            if "listening on" not in line:
                raise RuntimeError(f"stopbard did not start: {line!r} {proc.stderr.read()}")
            addr = line.rsplit(" ", 1)[1].strip()
            signed = 0
            for i, body in enumerate(steps[:stop_at]):
                sent = tpl.render(body)
                status, d = post(addr, sent)
                if status != 200:
                    problems.append(f"step {i} should be allowed, got {status} {d.get('reasons')}")
                    continue
                problems += check_signed(i, sent, d)
                signed += 1
            status, d = post(addr, tpl.render(steps[stop_at]))
            if status == 400:  # gateway error body: normalise to a rejection
                d = {"outcome": "reject", "reasons": [{"code": d.get("code")}], "request_id": d.get("request_id")}
            got_ids = sorted(r["policy_id"] for r in d.get("reasons", []) if r.get("policy_id"))
            codes = [r.get("code") for r in d.get("reasons", [])]
            if status != STATUS[want["outcome"]] or d.get("outcome") != want["outcome"]:
                problems.append(f"step {stop_at}: HTTP {status} {d.get('outcome')}, want {STATUS[want['outcome']]} {want['outcome']}")
            if got_ids != sorted(want.get("policy_ids", [])):
                problems.append(f"policy_ids {got_ids}, want {want.get('policy_ids', [])}")
            if want.get("code") and want["code"] not in codes:
                problems.append(f"reason codes {codes}, want {want['code']}")
            with urllib.request.urlopen(f"http://{addr}/v1/keys", timeout=5) as r:
                open(keys, "wb").write(r.read())  # published keys: all verify needs, besides the file
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        # Offline, after shutdown: the run's own audit log must verify, with
        # every record covered by a signed checkpoint (one is signed at exit).
        # A reject at the very first step records nothing: the log is
        # legitimately empty only then.
        empty_ok = ["--allow-empty"] if want["outcome"] == "reject" and stop_at == 0 else []
        v = subprocess.run([stopbar_cli, "audit", "verify", "--state-dir", state, "--keys", keys, "--require-covered", *empty_ok],
                           capture_output=True, text=True)
        print("    ", (v.stdout or v.stderr).strip())
        if v.returncode != 0:
            problems.append("audit verify failed")
        else:
            ex = subprocess.run([stopbar_cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
            recs = [json.loads(l) for l in ex.stdout.splitlines()]
            stop_id = steps[stop_at]["id"]
            decisions = sum(1 for r in recs if r["type"] == "decision" and r["body"]["decision"]["request_id"] == stop_id)
            earlier = sum(1 for st in steps[:stop_at] if st["id"] == stop_id)
            want_decisions = earlier if want["outcome"] == "reject" else earlier + 1
            if decisions != want_decisions:
                problems.append(f"{decisions} audited decisions for {stop_id}, want {want_decisions}"
                                + (" (a rejected request reached the engine)" if want["outcome"] == "reject" else ""))
            commits = sum(1 for r in recs if r["type"] == "commit")
            if commits != signed:
                problems.append(f"{commits} commit records for {signed} signed transactions")
    failures += bool(problems)
    seq = f" at step {stop_at + 1}/{len(steps)}" if len(steps) > 1 else ""
    print("ok  " if not problems else "FAIL",
          f"{entry['id']}: HTTP {status} {d.get('outcome')}{seq} {got_ids or codes}", "; ".join(problems))

sys.exit(failures)
