"""Tool-call smoke test against a live stopbard running a tool-call bundle (scripts/e2e.sh).

Usage: e2e_toolcall.py PATH/TO/stopbard BUNDLE_DIR
A synthetic session, built from tool names only (no AgentDojo task): clean
state changes are allowed; reading an untrusted-output tool taints the session;
the next state-changing call is denied; reads stay allowed; an undeclared
tool fails closed; a call without a session ID fails closed.
"""
import base64, datetime, json, os, subprocess, sys, tempfile, urllib.error, urllib.request

stopbard, bundle = sys.argv[1], sys.argv[2]
failures = 0


def req(i, tool, session="sess-1", args=None):
    actor = {"agent_id": "pilot-agent"}
    if session:
        actor["session_id"] = session
    return {"id": f"req_tool_{i}", "tenant": "test", "nonce": base64.urlsafe_b64encode(os.urandom(18)).decode(),
            "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ttl_seconds": 60, "actor": actor, "action": {"kind": "tool_call", "tool": tool, "args": args or {}},
            "provenance": {"labels": ["trusted_user"]}}


with tempfile.TemporaryDirectory() as tmp:
    world = os.path.join(tmp, "world.json")
    json.dump({"limits_disabled": True}, open(world, "w"))
    proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-policies", bundle],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        if "listening on" not in line:
            raise SystemExit(f"stopbard did not start: {line!r} {proc.stderr.read()}")
        addr = line.rsplit(" ", 1)[1].strip()
        for i, (name, body, want_status, want) in enumerate([
            ("clean transfer allowed", req(0, "send_money", "clean", {"recipient": "X", "amount": 1}), 200, None),
            ("clean identity change allowed (no identity rule in the pilot pack)", req(1, "update_password", "clean", {"password": "p"}), 200, None),
            ("untrusted read allowed", req(2, "read_file", args={"file_path": "f"}), 200, None),
            ("state change after untrusted read denied", req(3, "send_money", args={"recipient": "X", "amount": 1}), 403, "tainted-state-change"),
            ("reads stay allowed", req(4, "get_balance"), 200, None),
            ("undeclared tool fails closed", req(5, "transfer_everything"), 403, "FAIL_CLOSED_POLICY"),
            ("no session id fails closed", req(6, "send_money", session=None), 403, "FAIL_CLOSED_ENRICH"),
        ]):
            r = urllib.request.Request(f"http://{addr}/v1/evaluate", data=json.dumps(body).encode(), method="POST",
                                       headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(r, timeout=5) as resp:
                    status, d = resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                status, d = e.code, json.loads(e.read())
            got = [x.get("policy_id") or x.get("code") for x in d.get("reasons", [])]
            ok = status == want_status and (want is None or want in got)
            failures += not ok
            print("ok  " if ok else "FAIL", f"{name}: HTTP {status} {got}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
sys.exit(failures)
