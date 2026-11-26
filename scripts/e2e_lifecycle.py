"""Reservation and escalation lifecycle through a live stopbard over HTTP
(CS-105, CS-151 signed approve/reject, CS-152; scripts/e2e.sh).

Usage: e2e_lifecycle.py PATH/TO/stopbard PATH/TO/stopbar

stopbard runs in advisory mode with authentication, an agent-scope count cap
of 1 per hour (so a held reservation visibly blocks the next allow), and
-approval-quorum 1 (allowed only with -dev-world, CS-151 — -breaker-quorum
has no such exception and stays at its default 2, unused by this script): a
single signed vote reaches quorum for escalation approvals, so this script's
focus stays on the lifecycle itself (reservations, poll, expiry,
self-approval, commit after approval) rather than M-of-N mechanics, which
scripts/e2e_breaker.py and the SDK examples already cover with a real 2-of-N
quorum.

  reservations  evaluate (reserve) → a second allow is CAP_EXCEEDED → release
                frees it → evaluate → commit consumes it for good (release now
                409, the next allow CAP_EXCEEDED); retries are idempotent; other
                agents, approver keys and unknown ids cannot settle it.
  escalations   escalate → poll 202 pending → the REAL `stopbar reject <id>
                --approver-key FILE` (id before flags) signs and submits a
                reject → poll 403 denied, approve now 409; a bare POST with no
                signed envelope is refused (CS-151: no API-call approval left);
                the requester cannot *approve* its own escalation even with an
                approver key bound to its own identity (self-approval; a
                self-reject is allowed by design, spec/approval-signature-v1.md
                §7); `stopbar approve <id> --approver-key FILE` → 200 allow
                with a token → poll 200 allowed → commit; an escalation left
                past -pending-ttl polls 403 expired.

  gatekeeper    a second stopbard holding the wallet (-dev-wallet): escalate →
                `stopbar approve <id> --approver-key FILE` → 200 with a signed
                tx that `stopbar decode-tx` recovers to `from` with the
                decision's payload hash; the poll returns the same signed tx;
                the tx is committed.

After each shutdown `stopbar audit verify --require-covered` must pass, and the
log must hold each lifecycle record with the identity that caused it.
Needs: pyyaml.
"""
import base64, datetime, hashlib, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))
import stopbar  # noqa: E402

stopbard, stopbar_cli = sys.argv[1], sys.argv[2]
PENDING_TTL = 6  # seconds; the expiry check waits it out
failures = []


def check(cond, what):
    print("ok  " if cond else "FAIL", what)
    if not cond:
        failures.append(what)


def template(path, agent, rid):
    """A corpus request as a fresh template: new id, nonce, issued_at, agent."""
    entry = yaml.safe_load(open(path))
    r = dict((entry.get("requests") or [entry["request"]])[0])
    r["id"], r["actor"] = rid, {"agent_id": agent}
    r["nonce"] = base64.urlsafe_b64encode(os.urandom(18)).decode()
    r["issued_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return r, entry["setup"]


def http(addr, method, path, key=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(f"http://{addr}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def codes(d):
    return [r.get("code") for r in d.get("reasons", [])]


def approver_keygen(path):
    """`stopbar approver keygen <path>`; returns the base64url public key."""
    r = subprocess.run([stopbar_cli, "approver", "keygen", path], capture_output=True, text=True, check=True)
    return next(l.rsplit(": ", 1)[1].strip() for l in r.stdout.splitlines() if l.startswith("public_key"))


def cli_approve(rid, addr, approver_key, api_key, verb="approve"):
    # --yes: a script cannot answer the confirmation prompt (CS-143); the rendering still goes to stderr.
    return subprocess.run([stopbar_cli, verb, rid, "--url", f"http://{addr}", "--approver-key", approver_key, "--key", api_key, "--yes"],
                          capture_output=True, text=True)


ALLOW = "corpus/attacks/CS-2026-0005-replayed-request.yaml"   # 1% of balance to a known address: allowed
ESCALATE = "corpus/attacks/CS-2026-0002-agent-over-transfer.yaml"  # 100% of balance: escalates
_, setup = template(ALLOW, "x", "x")
setup = dict(setup, limits=[{"scope": "agent", "window": "1h", "max_count": 1}])

keys = {  # name: (secret, tenant, agent, scopes) — scopes are now cosmetic for
    # approve/reject/breaker (CS-151 moved authorization to the signature);
    # they still gate /v1/evaluate and /v1/actions.
    "defi": ("stopbar_sk_e2e_defi", "test", "defi-agent", ["evaluate"]),
    "esc": ("stopbar_sk_e2e_esc", "test", "esc-agent", ["evaluate"]),
    "other": ("stopbar_sk_e2e_other", "test", "other-agent", ["evaluate"]),
    "ops": ("stopbar_sk_e2e_ops", "test", "", ["approve"]),
    "dual": ("stopbar_sk_e2e_dual", "test", "dual-agent", ["evaluate", "approve"]),  # to try self-approval
    "sdk": ("stopbar_sk_e2e_sdk", "test", "sdk-agent", ["evaluate"]),
}
K = {n: v[0] for n, v in keys.items()}


def write_auth_keys(path):
    json.dump([{"id": "ak_" + n, "tenant": t, "agent_id": a, "scopes": s, "sha256": hashlib.sha256(sec.encode()).hexdigest()}
               for n, (sec, t, a, s) in keys.items()], open(path, "w"))


with tempfile.TemporaryDirectory() as tmp:
    world, keyfile, jwks, state = (os.path.join(tmp, f) for f in ("world.json", "auth.json", "jwks.json", "state"))
    ops_key, dual_key, approvers_file = (os.path.join(tmp, f) for f in ("ops.key", "dual.key", "approvers.json"))
    json.dump(setup, open(world, "w"))
    write_auth_keys(keyfile)
    # ops_key is a neutral approver (bound to no requester); dual_key is bound
    # to the "dual" API key's identity, for the self-approval test below.
    ops_pub, dual_pub = approver_keygen(ops_key), approver_keygen(dual_key)
    json.dump({"approvers": [
        {"id": "ops", "tenant": "test", "owner": {"key_id": "ak_ops_signer"}, "public_key": ops_pub},
        {"id": "dual_approver", "tenant": "test", "owner": {"key_id": "ak_dual"}, "public_key": dual_pub},
    ]}, open(approvers_file, "w"))
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-auth-keys", keyfile,
                             "-approvers", approvers_file, "-approval-quorum", "1",
                             "-state-dir", state, "-pending-ttl", f"{PENDING_TTL}s"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        if "listening on" not in line:
            raise RuntimeError(f"stopbard did not start: {line!r} {proc.stderr.read()}")
        addr = line.rsplit(" ", 1)[1].strip()

        print("-- reservations (CS-105)")
        a1, _ = template(ALLOW, "defi-agent", "req_life_a1")
        s, d = http(addr, "POST", "/v1/evaluate", K["defi"], a1)
        check(s == 200 and d.get("reservation_id") == "req_life_a1" and d.get("token"), f"evaluate reserves: HTTP {s} {codes(d)}")
        s, d = http(addr, "POST", "/v1/evaluate", K["defi"], template(ALLOW, "defi-agent", "req_life_a2")[0])
        check(s == 403 and "CAP_EXCEEDED" in codes(d), f"the held reservation fills the cap: HTTP {s} {codes(d)}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/release", K["other"], {})
        check(s == 404, f"another agent cannot release it: HTTP {s} {d.get('code')}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/release", K["ops"], {})
        check(s == 403 and d.get("code") == "FORBIDDEN_SCOPE", f"an approver key cannot release it: HTTP {s} {d.get('code')}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/release", None, {})
        check(s == 401, f"release needs a credential: HTTP {s}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/release", K["defi"], {"reason": "user cancelled"})
        check(s == 200 and d.get("state") == "released", f"release frees it: HTTP {s} {d}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/release", K["defi"], {"reason": "retry"})
        check(s == 200, f"release again is idempotent: HTTP {s} {d}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a1/commit", K["defi"], {"tx_ref": "0x01"})
        check(s == 404, f"a released reservation cannot be committed: HTTP {s} {d.get('code')}")
        s, d = http(addr, "POST", "/v1/evaluate", K["defi"], template(ALLOW, "defi-agent", "req_life_a3")[0])
        check(s == 200, f"capacity is back after release: HTTP {s} {codes(d)}")
        tx = "0x" + "ab" * 32
        s, d = http(addr, "POST", "/v1/actions/req_life_a3/commit", K["defi"], {"tx_ref": tx})
        check(s == 200 and d.get("state") == "committed", f"commit: HTTP {s} {d}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a3/commit", K["defi"], {"tx_ref": tx})
        check(s == 200, f"commit again with the same tx_ref is idempotent: HTTP {s}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a3/commit", K["defi"], {"tx_ref": "0x02"})
        check(s == 409 and d.get("code") == "CONFLICT", f"commit with another tx_ref: HTTP {s} {d.get('code')}")
        s, d = http(addr, "POST", "/v1/actions/req_life_a3/release", K["defi"], {})
        check(s == 409, f"a committed reservation cannot be released: HTTP {s} {d.get('code')}")
        s, d = http(addr, "POST", "/v1/evaluate", K["defi"], template(ALLOW, "defi-agent", "req_life_a4")[0])
        check(s == 403 and "CAP_EXCEEDED" in codes(d), f"the commit consumed the cap: HTTP {s} {codes(d)}")
        s, d = http(addr, "POST", "/v1/actions/req_nope/commit", K["defi"], {"tx_ref": tx})
        check(s == 404, f"unknown id: HTTP {s}")

        print("-- escalations (CS-151 signed approve/reject, CS-152)")
        e1, _ = template(ESCALATE, "esc-agent", "req_life_e1")
        s, d = http(addr, "POST", "/v1/evaluate", K["esc"], e1)
        check(s == 202, f"escalates: HTTP {s} {d.get('reasons')}")
        s, d = http(addr, "GET", "/v1/decisions/req_life_e1", K["esc"])
        check(s == 202 and d.get("state") == "pending" and d["decision"]["outcome"] == "escalate", f"poll pending: HTTP {s} {d.get('state')}")
        s, d = http(addr, "GET", "/v1/decisions/req_life_e1", K["other"])
        check(s == 404, f"another agent cannot poll it: HTTP {s}")
        s, d = http(addr, "POST", "/v1/approvals/req_life_e1/reject", K["esc"])
        check(s == 415 and d.get("code") == "UNSUPPORTED_MEDIA_TYPE",
              f"a bare POST with no signed envelope is refused (CS-151: no API-call approval left): HTTP {s} {d.get('code')}")
        r = cli_approve("req_life_e1", addr, ops_key, K["ops"], "reject")
        check(r.returncode == 0 and "APPROVAL_REJECTED" in r.stdout, f"`stopbar reject <id> --approver-key --url --key` exits 0: {r.returncode} {r.stderr.strip()}")
        s, d = http(addr, "GET", "/v1/decisions/req_life_e1", K["esc"])
        check(s == 403 and d.get("state") == "denied" and "APPROVAL_REJECTED" in codes(d["decision"]),
              f"poll denied: HTTP {s} {d.get('state')}")
        r = cli_approve("req_life_e1", addr, ops_key, K["ops"], "approve")
        # Resolved: GET /v1/approvals/<id> (what-to-sign) now 404s, same as an
        # unknown id — the CLI fails at that step, before any POST/409.
        check(r.returncode != 0 and "404" in r.stderr, f"approve after reject is refused: {r.stderr.strip()}")

        e2, _ = template(ESCALATE, "esc-agent", "req_life_e2")
        s, d = http(addr, "POST", "/v1/evaluate", K["esc"], e2)
        check(s == 202, f"second escalation: HTTP {s}")
        r = cli_approve("req_life_e2", addr, ops_key, K["ops"], "approve")
        check(r.returncode == 0 and '"outcome": "allow"' in r.stdout and '"token"' in r.stdout, f"`stopbar approve <id>` allows with a token: {r.returncode} {r.stderr.strip()}")
        s, d = http(addr, "GET", "/v1/decisions/req_life_e2", K["esc"])
        check(s == 200 and d.get("state") == "allowed" and d["decision"].get("token"), f"poll allowed, with the token: HTTP {s} {d.get('state')}")
        s, d = http(addr, "POST", "/v1/actions/req_life_e2/commit", K["esc"], {"tx_ref": "0x" + "cd" * 32})
        check(s == 200, f"the requester commits the approved allow: HTTP {s} {d}")

        e4, _ = template(ESCALATE, "dual-agent", "req_life_e4")
        s, d = http(addr, "POST", "/v1/evaluate", K["dual"], e4)
        # dual_key's owner (ak_dual) is bound to dual-agent's own requester
        # identity: approving its own escalation is refused (self-approval).
        # A self-REJECT, by contrast, is allowed by design (spec §7) — not
        # re-tested here; it is covered directly in internal/engine's tests.
        r = cli_approve("req_life_e4", addr, dual_key, K["dual"], "approve")
        s2, d2 = http(addr, "GET", "/v1/decisions/req_life_e4", K["dual"])
        check(s == 202 and r.returncode != 0 and "APPROVAL_SELF_APPROVAL" in r.stdout and d2.get("state") == "pending",
              f"the requester cannot approve its own escalation, even with an approver key bound to its identity (still {d2.get('state')})")

        print("-- the Python SDK against the same stopbard")
        sb = stopbar.Client(f"http://{addr}", api_key=K["sdk"], tenant="test", agent_id="sdk-agent")
        req = template(ALLOW, "sdk-agent", "x")[0]
        d = sb.evaluate(req["action"], labels=["trusted_user"], request_id="req_life_s1")
        check(sb.release(d.request_id, "sdk cancel")["state"] == "released", "sdk: evaluate → release")
        d = sb.evaluate(req["action"], labels=["trusted_user"], request_id="req_life_s2")
        check(sb.commit(d.request_id, "0x" + "ef" * 32)["state"] == "committed", "sdk: evaluate → commit")
        try:
            sb.release(d.request_id)
            check(False, "sdk: release after commit must raise")
        except stopbar.StopbarRequestError as e:
            check(e.code == "CONFLICT", f"sdk: release after commit raises CONFLICT ({e.code})")
        esc = template(ESCALATE, "sdk-agent", "x")[0]
        try:
            sb.evaluate(esc["action"], labels=["trusted_user"], request_id="req_life_s3")
            check(False, "sdk: the escalation must raise StopbarEscalated")
        except stopbar.StopbarEscalated as e:
            check(sb.poll(e.request_id).state == "pending", "sdk: escalate → poll pending")
            # The SDK signs locally with the same ops.key file the CLI used above.
            check(sb.reject(e.request_id, ops_key).reasons == ["APPROVAL_REJECTED"], "sdk: signs and submits a reject")
            st = sb.poll(e.request_id)
            check(st.state == "denied" and not st.allowed and st.decision.outcome == "deny", "sdk: poll denied")

        e3, _ = template(ESCALATE, "esc-agent", "req_life_e3")
        s, d = http(addr, "POST", "/v1/evaluate", K["esc"], e3)
        check(s == 202, f"third escalation: HTTP {s}")
        time.sleep(PENDING_TTL + 1)
        s, d = http(addr, "GET", "/v1/decisions/req_life_e3", K["ops"])
        check(s == 403 and d.get("state") == "expired" and "APPROVAL_EXPIRED" in codes(d["decision"]), f"timeout → deny: HTTP {s} {d.get('state')}")
        r = cli_approve("req_life_e3", addr, ops_key, K["ops"], "reject")
        check(r.returncode != 0 and "404" in r.stderr, "reject after expiry is refused (resolved as expired; GET 404s)")

        with urllib.request.urlopen(f"http://{addr}/v1/keys", timeout=5) as resp:
            open(jwks, "wb").write(resp.read())
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    v = subprocess.run([stopbar_cli, "audit", "verify", "--state-dir", state, "--keys", jwks, "--require-covered"], capture_output=True, text=True)
    check(v.returncode == 0, f"audit verify: {(v.stdout or v.stderr).strip()}")
    ex = subprocess.run([stopbar_cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    recs = [json.loads(l) for l in ex.stdout.splitlines()]

    def find(typ, pred):
        return [r["body"] for r in recs if r["type"] == typ and pred(r["body"])]

    def last_code(b):
        return (b.get("decision", {}).get("reasons") or [{}])[-1].get("code")

    who = lambda b: (b.get("identity") or {}).get("key_id")
    check(any(who(b) == "ak_defi" for b in find("release", lambda b: b["request_id"] == "req_life_a1")), "release audited with the requester identity")
    check(len(find("release", lambda b: b["request_id"] == "req_life_a1")) == 1, "the idempotent second release wrote nothing")
    check(any(who(b) == "ak_defi" and b["tx_ref"] == tx for b in find("commit", lambda b: b["request_id"] == "req_life_a3")), "commit audited with tx_ref and identity")
    check(any(who(b) == "ak_ops" and (b.get("veto") or {}).get("kid") for b in find("decision", lambda b: last_code(b) == "APPROVAL_REJECTED")),
          "reject audited with the rejecting owner's kid (not an API-key label)")
    check(any(who(b) == "ak_ops" and b["state"] == "allowed" for b in find("approval", lambda b: b["request_id"] == "req_life_e2")), "approval resolution audited")
    check(any(b["decision"]["request_id"] == "req_life_e3" for b in find("decision", lambda b: last_code(b) == "APPROVAL_EXPIRED")), "expiry audited as a deny")
    check(any(who(b) == "ak_other" for b in find("auth_reject", lambda b: "not the requester" in b.get("reason", ""))), "a foreign settle attempt is audited")

print("-- gatekeeper: escalate → approve → signed tx (CS-152 acceptance)")
ANVIL_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # public test key, never funded
with tempfile.TemporaryDirectory() as tmp:
    world, keyfile, wallet, jwks, state = (os.path.join(tmp, f) for f in ("world.json", "auth.json", "wallet", "jwks.json", "state"))
    ops_key, approvers_file = os.path.join(tmp, "ops.key"), os.path.join(tmp, "approvers.json")
    json.dump(setup, open(world, "w"))
    write_auth_keys(keyfile)
    ops_pub = approver_keygen(ops_key)
    json.dump({"approvers": [{"id": "ops", "tenant": "test", "owner": {"key_id": "ak_ops_signer"}, "public_key": ops_pub}]}, open(approvers_file, "w"))
    with open(os.open(wallet, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
        f.write("stopbar-dev-wallet-secp256k1-v1\n" + ANVIL_KEY + "\n")
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-wallet", wallet,
                             "-auth-keys", keyfile, "-approvers", approvers_file, "-approval-quorum", "1", "-state-dir", state],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        if "listening on" not in line:
            raise RuntimeError(f"stopbard did not start: {line!r} {proc.stderr.read()}")
        addr = line.rsplit(" ", 1)[1].strip()
        g1, _ = template(ESCALATE, "esc-agent", "req_life_g1")
        s, d = http(addr, "POST", "/v1/evaluate", K["esc"], g1)
        check(s == 202, f"gatekeeper: escalates: HTTP {s}")
        r = cli_approve("req_life_g1", addr, ops_key, K["ops"], "approve")
        out = r.stdout.split("\n", 1)[1] if "\n" in r.stdout else "{}"
        d = json.loads(out or "{}")
        check(r.returncode == 0 and d.get("outcome") == "allow" and d.get("signed_tx"), f"gatekeeper: `stopbar approve` returns a signed tx ({r.returncode})")
        if d.get("signed_tx"):
            tx = json.loads(subprocess.run([stopbar_cli, "decode-tx", d["signed_tx"]], capture_output=True, text=True, check=True).stdout)
            check(tx["action"]["from"] == g1["action"]["from"].lower() and tx["payload_hash"] == d["payload_hash"] and tx["tx_hash"] == d["tx_hash"],
                  "gatekeeper: decode-tx recovers `from` and the decision's payload hash")
        s, st = http(addr, "GET", "/v1/decisions/req_life_g1", K["esc"])
        check(s == 200 and st.get("state") == "allowed" and st["decision"].get("signed_tx") == d.get("signed_tx"),
              f"gatekeeper: the requester's poll returns the signed tx: HTTP {s} {st.get('state')}")
        s, c = http(addr, "POST", "/v1/actions/req_life_g1/commit", K["esc"], {"tx_ref": d.get("tx_hash") or "0x"})
        check(s == 200, f"gatekeeper: already committed by the adapter; the same tx_ref is idempotent: HTTP {s}")
        with urllib.request.urlopen(f"http://{addr}/v1/keys", timeout=5) as resp:
            open(jwks, "wb").write(resp.read())
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    v = subprocess.run([stopbar_cli, "audit", "verify", "--state-dir", state, "--keys", jwks, "--require-covered"], capture_output=True, text=True)
    check(v.returncode == 0, f"gatekeeper audit verify: {(v.stdout or v.stderr).strip()}")
    ex = subprocess.run([stopbar_cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    recs = [json.loads(l) for l in ex.stdout.splitlines()]
    check(any(r["type"] == "commit" and r["body"]["request_id"] == "req_life_g1" for r in recs), "gatekeeper: the signed tx has a commit record")
    check(any(r["type"] == "approval" and r["body"]["state"] == "allowed" and r["body"]["decision"].get("signed_tx") for r in recs),
          "gatekeeper: the approval resolution records the signed tx")

print(f"\n{'FAIL' if failures else 'ok  '} lifecycle e2e: {len(failures)} failures")
sys.exit(1 if failures else 0)
