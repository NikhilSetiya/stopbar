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
given, and so must every step after it (a tripped circuit breaker keeps
denying). Counters in expected.metrics must match /metrics. After shutdown, `stopbar audit verify --require-covered` must pass over
the run's own audit log, the stopping decision must be audited (a reject must
not reach the engine), and every signed tx must have a commit record. stopbard runs in gatekeeper mode: every allowed step must
return a signed tx, which `stopbar decode-tx` decodes independently. Its
recovered sender must equal `from` and its payload hash the decision's. Its
decision token must be v2 and bind the requester identity: method "none" here
(auth off), and, in a final run with -auth-keys, the authenticated API key
(CS-103, spec/decision-token-v2.md).
Needs: pyyaml.
"""
import base64, glob, hashlib, json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
from corpus_template import Templater

STATUS = {"allow": 200, "escalate": 202, "deny": 403, "reject": 400}
stopbard, stopbar_cli = sys.argv[1], sys.argv[2]
# Anvil test account 0: a public test key, never funded. Corpus `from`
# addresses use it, so gatekeeper mode can sign the allowed steps.
ANVIL_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
failures = 0


def post(addr, body, bearer=None, path="/v1/evaluate"):
    raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    if raw:
        print("     sent:", raw.decode())  # the rewritten bytes, so every run is reproducible from its log
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(f"http://{addr}{path}", data=raw, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def token_claims(tok):
    seg = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def check_signed(i, sent, d, identity=("none", "", "")):
    """An allow must carry a signed tx (or, for an off-chain request, a
    signature) that does exactly what was approved, and a v2 token bound to the
    requester identity (method, key_id, agent_id)."""
    offchain = sent["action"]["kind"] in ("evm_typed_data", "evm_personal_sign")
    if not d.get("signature" if offchain else "signed_tx") or not d.get("token"):
        return [f"step {i}: allow without {'signature' if offchain else 'signed_tx'}/token"]
    c = token_claims(d["token"])
    if c.get("v") != 2 or (c.get("auth_method"), c.get("key_id"), c.get("agent_id")) != identity:
        return [f"step {i}: token v{c.get('v')} binds {c.get('auth_method')}/{c.get('key_id')}/{c.get('agent_id')}, want v2 {'/'.join(identity)}"]
    if offchain:  # CS-514: recompute the digest and recover the signer independently
        out = subprocess.run([stopbar_cli, "decode-sig", "-", d["signature"]], input=json.dumps(sent["action"]), capture_output=True, text=True)
        if out.returncode != 0:
            return [f"step {i}: decode-sig failed: {out.stderr.strip()}"]
        s = json.loads(out.stdout)
        errs = [f"step {i}: {k} {s[k]} != {v}" for k, v in (("signer", sent["action"]["from"].lower()), ("signing_hash", d.get("signing_hash")),
                                                            ("payload_hash", d["payload_hash"])) if s[k] != v]
        if not errs:
            print(f"     step {i}: off-chain signature by {s['signer']} over {s['signing_hash'][:18]}…, payload and requester ({identity[0]}) bound")
        return errs
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
        print(f"     step {i}: signed by {tx['action']['from']}, tx {tx['tx_hash'][:18]}…, payload and requester ({identity[0]}) bound")
    return errs


def start(tmp, world_setup, *extra):
    """Start a gatekeeper-mode stopbard on world_setup; returns (proc, addr, state, keys)."""
    world, wallet, keys, state = (os.path.join(tmp, f) for f in ("world.json", "wallet", "keys.json", "state"))
    json.dump(world_setup, open(world, "w"))
    with open(os.open(wallet, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + ANVIL_KEY + "\n")
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-wallet", wallet,
                             "-state-dir", state, "-audit-checkpoint-every", "2", *extra],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if "listening on" not in line:
        proc.kill()
        raise RuntimeError(f"stopbard did not start: {line!r} {proc.stderr.read()}")
    return proc, line.rsplit(" ", 1)[1].strip(), state, keys


for path in sorted(glob.glob("corpus/attacks/*.yaml")):
    entry = yaml.safe_load(open(path))
    want = entry["expected"]
    steps = entry.get("requests") or [entry["request"]]
    stop_at = want.get("at_step", len(steps) - 1)
    problems = []
    setup = dict(entry.get("setup", {}))
    tpl = Templater(setup.pop("issued_at_offset", "0s"))
    with tempfile.TemporaryDirectory() as tmp:
        proc, addr, state, keys = start(tmp, setup)
        try:
            signed = 0
            for i, body in enumerate(steps[:stop_at]):
                sent = tpl.render(body)
                status, d = post(addr, sent)
                if status != 200:
                    problems.append(f"step {i} should be allowed, got {status} {d.get('reasons')}")
                    continue
                problems += check_signed(i, sent, d)
                signed += 1
            # The stopping step, and every step after it, must be stopped the
            # same way (e.g. a tripped circuit breaker keeps denying).
            for j in range(stop_at, len(steps)):
                st, dj = post(addr, tpl.render(steps[j]))
                if st == 400:  # gateway error body: normalise to a rejection
                    dj = {"outcome": "reject", "reasons": [{"code": dj.get("code")}], "request_id": dj.get("request_id")}
                ids = sorted(r["policy_id"] for r in dj.get("reasons", []) if r.get("policy_id"))
                cs = [r.get("code") for r in dj.get("reasons", [])]
                if st != STATUS[want["outcome"]] or dj.get("outcome") != want["outcome"]:
                    problems.append(f"step {j}: HTTP {st} {dj.get('outcome')}, want {STATUS[want['outcome']]} {want['outcome']}")
                if ids != sorted(want.get("policy_ids", [])):
                    problems.append(f"step {j}: policy_ids {ids}, want {want.get('policy_ids', [])}")
                if want.get("code") and want["code"] not in cs:
                    problems.append(f"step {j}: reason codes {cs}, want {want['code']}")
                if j == stop_at:
                    status, d, got_ids, codes = st, dj, ids, cs
            if want.get("metrics"):
                with urllib.request.urlopen(f"http://{addr}/metrics", timeout=5) as r:
                    lines = dict(l.rsplit(" ", 1) for l in r.read().decode().splitlines() if l and not l.startswith("#"))
                for name, v in want["metrics"].items():
                    if lines.get(name) != str(v):
                        problems.append(f"metric {name} = {lines.get(name)}, want {v}")
                    else:
                        print(f"     /metrics: {name} {v}")
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

# Authenticated gatekeeper (CS-103 increment 2). With -auth-keys, an allowed
# step sent with an API key is signed only under a v2 token that binds that key
# and its agent (never the body's claim). An escalation approved by two signed
# approver votes (CS-151, 2-of-2) is signed under a token that binds the
# requester, not the approvers.
entries = [yaml.safe_load(open(p)) for p in sorted(glob.glob("corpus/attacks/*.yaml"))]
cases = [(next(e for e in entries if e["expected"].get("at_step", 0) > 0), 0, False),
         (next(e for e in entries if e["expected"]["outcome"] == "escalate" and "requests" not in e), 0, True)]
for entry, step, approve in cases:
    setup = dict(entry.get("setup", {}))
    tpl = Templater(setup.pop("issued_at_offset", "0s"))
    if approve:  # the approval re-run re-checks the caps, which this full-balance transfer exceeds; identity is under test here
        setup.pop("limits", None)  # CS-2026-0002 carries hard per-tx caps (CS-123) that would deny the approval
        setup["limits_disabled"] = True
    body = tpl.render((entry.get("requests") or [entry["request"]])[step])
    secret, approver = ("e2e-" + os.urandom(16).hex() for _ in range(2))
    keyrec = lambda kid, agent, scope, sec: {"id": kid, "tenant": body["tenant"], "agent_id": agent, "scopes": [scope],
                                             "sha256": hashlib.sha256(sec.encode()).hexdigest()}
    want_id = ("api_key", "ak_e2e", body["actor"]["agent_id"])
    with tempfile.TemporaryDirectory() as tmp:
        keyfile = os.path.join(tmp, "api-keys.json")
        json.dump([keyrec("ak_e2e", body["actor"]["agent_id"], "evaluate", secret),
                   keyrec("ak_e2e_approver", "ops", "approve", approver)], open(keyfile, "w"))
        approvers = []
        for who in ("alice", "bob"):
            kf = os.path.join(tmp, f"approver-{who}.key")
            out = subprocess.run([stopbar_cli, "approver", "keygen", kf], capture_output=True, text=True, check=True).stdout
            pub = next(l.rsplit(": ", 1)[1].strip() for l in out.splitlines() if l.startswith("public_key"))
            approvers.append(({"id": who, "tenant": body["tenant"], "owner": {"agent_id": who}, "public_key": pub}, kf))
        json.dump({"approvers": [a for a, _ in approvers]}, open(os.path.join(tmp, "approvers.json"), "w"))
        proc, addr, _, _ = start(tmp, setup, "-auth-keys", keyfile, "-approvers", os.path.join(tmp, "approvers.json"), "-approval-quorum", "2")
        try:
            status, d = post(addr, body, bearer=secret)
            if approve and status == 202:
                for _, kf in approvers:  # `stopbar approve` signs locally; the second vote reaches quorum
                    out = subprocess.run([stopbar_cli, "approve", body["id"], "--url", f"http://{addr}", "--approver-key", kf, "--key", approver],
                                         capture_output=True, text=True).stdout
                    status, d = (int(out.split()[1]), json.loads(out.split("\n", 1)[1])) if out.startswith("HTTP ") else (0, {})
            problems = [f"HTTP {status} {d.get('reasons')}, want 200"] if status != 200 else check_signed(step, body, d, want_id)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    failures += bool(problems)
    what = "escalate -> approved 2-of-2 by signed approver keys" if approve else "allow"
    print("ok  " if not problems else "FAIL", f"authenticated gatekeeper, {entry['id']} {what}: token binds requester ak_e2e",
          "; ".join(problems))

sys.exit(failures)
