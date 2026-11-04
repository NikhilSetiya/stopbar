"""Replay every corpus attack through a live stopbard over HTTP (scripts/e2e.sh).

Usage: e2e_corpus.py PATH/TO/stopbard
For each corpus/attacks/*.yaml: start stopbard on the entry's `setup` (dev
stubs + the real engine and starter policy bundle), POST its request, and
require the expected outcome as the HTTP status (allow 200 / escalate 202 /
deny 403), exactly the expected policy IDs, and an audit record. Needs: pyyaml.
"""
import glob, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
import yaml

STATUS = {"allow": 200, "escalate": 202, "deny": 403}
stopbard = sys.argv[1]
failures = 0

for path in sorted(glob.glob("corpus/attacks/*.yaml")):
    entry = yaml.safe_load(open(path))
    want = entry["expected"]
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
            req = urllib.request.Request(f"http://{addr}/v1/evaluate", data=json.dumps(entry["request"]).encode(),
                                         method="POST", headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    status, body = r.status, r.read()
            except urllib.error.HTTPError as e:
                status, body = e.code, e.read()
            d = json.loads(body)
            got_ids = sorted(r["policy_id"] for r in d.get("reasons", []) if r.get("policy_id"))
            records = [json.loads(l) for l in open(audit)]
            audited = any(r["type"] == "decision" and r["body"]["decision"]["request_id"] == entry["request"]["id"]
                          for r in records)
            ok = (status == STATUS[want["outcome"]] and d.get("outcome") == want["outcome"]
                  and got_ids == sorted(want.get("policy_ids", [])) and audited)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    failures += not ok
    print("ok  " if ok else "FAIL", f"{entry['id']}: HTTP {status} {d.get('outcome')} {got_ids}",
          "" if ok else f"(want {STATUS[want['outcome']]} {want['outcome']} {want.get('policy_ids')}, audited={audited}; body {body[:300]!r})")

sys.exit(failures)
