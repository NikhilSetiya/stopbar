"""Live destination registry edits end to end (CS-134, CS-151, scripts/e2e.sh, CI go job).

Usage: e2e_contacts.py PATH/TO/stopbard PATH/TO/stopbar
stopbard runs with auth on (-auth-keys) and is never restarted to edit
contacts; `stopbar contacts` talks to it over /v1/contacts. API keys: bot
(evaluate), ops (contacts + approve) and alice (approve). Additions are
approved by Ed25519 approver signatures, 2 of N distinct owners (-approvers,
-approval-quorum 2): approver keys ops (bound to the requester), alice and bob.

Run A, default 24h cooling-off: a requested payee stays unknown while pending
and while cooling off (its look-alike is just a new destination: 200); the
requester-bound approver key is refused (SELF_APPROVAL); one signature leaves
it pending, the same owner again is DUPLICATE_VOTE, a second distinct owner
approves (cooling off); a look-alike request is
flagged with the entry it resembles; an exact duplicate is refused (409);
removal applies at once.
Run B, -contact-cooling-off 0s (no clock override: the server clock still
judges activation): two signatures -> active at once, so the look-alike escalates
(address-poisoning); after removal it is a new destination again, on the very
next request. Both audit logs verify, with every registry change recorded.
"""
import hashlib, json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
from corpus_template import Templater

stopbard, cli = sys.argv[1], sys.argv[2]
entry = yaml.safe_load(open("corpus/attacks/CS-2026-0011-address-poisoning.yaml"))
payee = entry["setup"]["known_destinations"][0]
lookalike = "0x7a25e0f3b9c4a8d27165e3f0a9b8c7d6e5f40c21"  # the corpus attacker's vanity address
to_payee, to_lookalike = entry["requests"]
tpl = Templater()
failures = 0
secrets = {name: "e2e-" + os.urandom(16).hex() for name in ("bot", "ops", "alice")}


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print("ok  " if ok else "FAIL", name + (f": {detail}" if detail else ""))


def serve(tmp, tag, *extra):
    state, key = os.path.join(tmp, f"state-{tag}"), os.path.join(tmp, f"decision-{tag}.key")
    subprocess.run([cli, "keygen", "decision-key", key], check=True, capture_output=True)
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", os.path.join(tmp, "world.json"),
                             "-state-dir", state, "-decision-key", key, "-auth-keys", os.path.join(tmp, "keys.json"),
                             "-approvers", os.path.join(tmp, "approvers.json"), "-approval-quorum", "2", *extra],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    line = proc.stdout.readline()
    if "listening on" not in line:
        raise SystemExit(f"stopbard did not start: {line!r}")
    return proc, "http://" + line.rsplit(" ", 1)[1].strip(), state, key


def evaluate(url, body, i):
    b = tpl.render(dict(body, id=f"{body['id']}_{i}", nonce=f"{body['nonce']}{i}"))
    r = urllib.request.Request(url + "/v1/evaluate", data=json.dumps(b).encode(), method="POST",
                               headers={"Content-Type": "application/json", "Authorization": "Bearer " + secrets["bot"]})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, d = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, d = e.code, json.loads(e.read())
    return status, [x.get("policy_id") or x.get("code") for x in d.get("reasons", [])]


def contacts(url, who, *args):
    out = subprocess.run([cli, "contacts", *args, "--url", url, "--key", secrets[who]], capture_output=True, text=True)
    return out.returncode, out.stdout + out.stderr


def approve(url, approver, cid):
    """`stopbar contacts approve` signed by approver's key; alice's API key carries it."""
    return contacts(url, "alice", "approve", cid, "--approver-key", approver_keys[approver])


def listing(url, who="alice"):
    r = urllib.request.Request(url + "/v1/contacts", headers={"Authorization": "Bearer " + secrets[who]})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return {c["address"]: c for c in json.loads(resp.read())["contacts"]}


def verify(state, key, want_types):
    v = subprocess.run([cli, "audit", "verify", "--state-dir", state, "--decision-key", key, "--require-covered"],
                       capture_output=True, text=True)
    check("audit verify --require-covered", v.returncode == 0, (v.stdout or v.stderr).strip().splitlines()[-1])
    ex = subprocess.run([cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    got = [json.loads(l)["type"] for l in ex.stdout.splitlines()]
    got = [t for t in got if t.startswith("contact_") or t == "auth_reject"]
    check("registry changes (and the self-approval refusal) audited", got == want_types, str(got))


with tempfile.TemporaryDirectory() as tmp:
    keyrec = lambda kid, agent, scopes: {"id": kid, "tenant": "test", "agent_id": agent, "scopes": scopes,
                                         "sha256": hashlib.sha256(secrets[kid].encode()).hexdigest()}
    json.dump([keyrec("bot", to_payee["actor"]["agent_id"], ["evaluate"]), keyrec("ops", "ops", ["contacts", "approve"]),
               keyrec("alice", "alice", ["approve"])], open(os.path.join(tmp, "keys.json"), "w"))
    approver_keys, entries = {}, []
    for who in ("ops", "alice", "bob"):
        approver_keys[who] = os.path.join(tmp, f"approver-{who}.key")
        r = subprocess.run([cli, "approver", "keygen", approver_keys[who]], capture_output=True, text=True, check=True)
        pub = next(l.rsplit(": ", 1)[1].strip() for l in r.stdout.splitlines() if l.startswith("public_key"))
        entries.append({"id": who, "tenant": "test", "owner": {"agent_id": who}, "public_key": pub})
    json.dump({"approvers": entries}, open(os.path.join(tmp, "approvers.json"), "w"))
    # The registry starts empty; several 2,500 USDC payments run, so a roomy cap keeps the limiter out of the way.
    json.dump(dict(entry["setup"], known_destinations=[], limits=[{"scope": "wallet", "window": "1h", "max_usd": "100000"}]),
              open(os.path.join(tmp, "world.json"), "w"))

    # ---- Run A: default cooling-off (24h) ----
    proc, url, state, key = serve(tmp, "a")
    try:
        status, got = evaluate(url, to_lookalike, 0)
        check("empty registry: look-alike is just a new destination", status == 200, f"HTTP {status} {got}")
        rc, out = contacts(url, "ops", "add", payee, "--label", "vendor")
        check("contacts add (live, no restart): pending", rc == 0 and "pending_approval" in out, out.strip().splitlines()[0])
        cid = listing(url)[payee]["id"]
        status, got = evaluate(url, to_lookalike, 1)
        check("pending payee is not known: look-alike still a new destination", status == 200, f"HTTP {status} {got}")
        rc, out = approve(url, "ops", cid)
        check("approver key bound to the requester refused", rc != 0 and "SELF_APPROVAL" in out, out.strip()[:100])
        check("still pending after the refused self-approval", listing(url)[payee]["status"] == "pending_approval")
        rc, out = contacts(url, "alice", "approve", cid)
        check("approve without an approver signature refused", rc != 0 and "usage" in out, out.strip()[:60])
        rc, out = approve(url, "alice", cid)
        check("one of two signatures: still pending", rc == 0 and "1 of 2 approvers" in out and listing(url)[payee]["status"] == "pending_approval",
              out.strip().splitlines()[-1])
        rc, out = approve(url, "alice", cid)
        check("the same approver again refused", rc != 0 and "DUPLICATE_VOTE" in out, out.strip()[:100])
        rc, out = approve(url, "bob", cid)
        check("second distinct owner signs: cooling off", rc == 0 and "cooling_off" in out, out.strip().splitlines()[-1])
        status, got = evaluate(url, to_lookalike, 2)
        check("cooling off: payee still unknown, look-alike still a new destination", status == 200, f"HTTP {status} {got}")
        rc, out = contacts(url, "ops", "add", lookalike)
        check("look-alike request flagged with the entry it resembles", rc == 0 and f'looks like existing entry {payee} "vendor"' in out,
              out.strip().splitlines()[-2] if rc == 0 else out.strip())
        sim = listing(url)[lookalike]["similar_to"]
        check("GET /v1/contacts shows the match to the approver", sim == [{"address": payee, "label": "vendor"}], str(sim))
        rc, out = contacts(url, "ops", "add", payee)
        check("exact duplicate refused", rc != 0 and "HTTP 409" in out, out.strip()[:80])
        rc, out = contacts(url, "ops", "remove", payee)
        check("remove applies at once", rc == 0 and payee not in listing(url), out.strip().splitlines()[-1])
        rc, out = approve(url, "bob", cid)
        check("a removed addition can no longer be approved", rc != 0 and "HTTP 404" in out, out.strip()[:80])
    finally:
        proc.terminate(); proc.wait(timeout=10)
    verify(state, key, ["contact_request", "auth_reject", "contact_approval", "contact_approval", "contact_request", "contact_removal"])

    # ---- Run B: no cooling-off, so activation and removal show on policy live ----
    proc, url, state, key = serve(tmp, "b", "-contact-cooling-off", "0s")
    try:
        contacts(url, "ops", "add", payee, "--label", "vendor")
        approve(url, "alice", listing(url)[payee]["id"])
        rc, out = approve(url, "bob", listing(url)[payee]["id"])
        check("cooling-off 0: two signatures -> active", rc == 0 and listing(url)[payee]["status"] == "active", out.strip().splitlines()[-1])
        status, got = evaluate(url, to_payee, 3)
        check("active payee allowed", status == 200, f"HTTP {status} {got}")
        status, got = evaluate(url, to_lookalike, 4)
        check("look-alike of an active payee escalates", status == 202 and got == ["address-poisoning"], f"HTTP {status} {got}")
        contacts(url, "ops", "remove", payee)
        status, got = evaluate(url, to_lookalike, 5)
        check("removed: the very next request treats the look-alike as new", status == 200, f"HTTP {status} {got}")
    finally:
        proc.terminate(); proc.wait(timeout=10)
    verify(state, key, ["contact_request", "contact_approval", "contact_approval", "contact_removal"])
sys.exit(failures)
