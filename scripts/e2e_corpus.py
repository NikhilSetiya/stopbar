"""Replay every corpus attack through a live stopbard over HTTP (scripts/e2e.sh, CI).

Usage: e2e_corpus.py PATH/TO/stopbard
For each corpus/attacks/*.yaml: start stopbard on the entry's `setup` (dev
stubs + the real engine, limiter and starter policy bundle) and POST its
request, or each request of its `requests` sequence in order. Every step
before expected.at_step must be allowed (200). The stopping step must have
the expected outcome as its HTTP status (allow 200 / escalate 202 / deny 403),
exactly the expected policy IDs, the expected reason code if one is given,
and an audit record. Needs: pyyaml.
"""
import glob, json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml

STATUS = {"allow": 200, "escalate": 202, "deny": 403}
stopbard = sys.argv[1]
failures = 0


def post(addr, body):
    req = urllib.request.Request(f"http://{addr}/v1/evaluate", data=json.dumps(body).encode(),
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


for path in sorted(glob.glob("corpus/attacks/*.yaml")):
    entry = yaml.safe_load(open(path))
    want = entry["expected"]
    steps = entry.get("requests") or [entry["request"]]
    stop_at = want.get("at_step", len(steps) - 1)
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        world, audit = os.path.join(tmp, "world.json"), os.path.join(tmp, "audit.jsonl")
        json.dump(entry.get("setup", {}), open(world, "w"))
        proc = subprocess.Popen([stopbard, "-listen", "127.0.0.1:0", "-dev-world", world, "-dev-audit", audit],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            if "listening on" not in line:
                raise RuntimeError(f"stopbard did not start: {line!r} {proc.stderr.read()}")
            addr = line.rsplit(" ", 1)[1].strip()
            for i, body in enumerate(steps[:stop_at]):
                status, d = post(addr, body)
                if status != 200:
                    problems.append(f"step {i} should be allowed, got {status} {d.get('reasons')}")
            status, d = post(addr, steps[stop_at])
            got_ids = sorted(r["policy_id"] for r in d.get("reasons", []) if r.get("policy_id"))
            codes = [r.get("code") for r in d.get("reasons", [])]
            if status != STATUS[want["outcome"]] or d.get("outcome") != want["outcome"]:
                problems.append(f"step {stop_at}: HTTP {status} {d.get('outcome')}, want {STATUS[want['outcome']]} {want['outcome']}")
            if got_ids != sorted(want.get("policy_ids", [])):
                problems.append(f"policy_ids {got_ids}, want {want.get('policy_ids', [])}")
            if want.get("code") and want["code"] not in codes:
                problems.append(f"reason codes {codes}, want {want['code']}")
            records = [json.loads(l) for l in open(audit)]
            if not any(r["type"] == "decision" and r["body"]["decision"]["request_id"] == steps[stop_at]["id"] for r in records):
                problems.append("stopping decision not audited")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    failures += bool(problems)
    seq = f" at step {stop_at + 1}/{len(steps)}" if len(steps) > 1 else ""
    print("ok  " if not problems else "FAIL",
          f"{entry['id']}: HTTP {status} {d.get('outcome')}{seq} {got_ids or codes}", "; ".join(problems))

sys.exit(failures)
