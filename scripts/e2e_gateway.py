"""End-to-end checks against a running stopbard (used by scripts/e2e.sh).

Usage: e2e_gateway.py http://127.0.0.1:PORT
Every fixture and corpus request must pass the gateway's structural checks;
until the engine lands (CS-104) that shows up as 503 ENGINE_UNAVAILABLE.
Hostile inputs must get their typed 4xx code. Needs: pyyaml.
"""
import glob, json, sys, urllib.error, urllib.request
import yaml
from corpus_template import Templater

base = sys.argv[1]
failures = 0


def call(method, path, body=None, ctype="application/json"):
    req = urllib.request.Request(base + path, data=body, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check(name, method, path, body, want_status, want_code=None, ctype="application/json"):
    global failures
    status, raw = call(method, path, body, ctype)
    code = None
    if want_code is not None:
        try:
            code = json.loads(raw).get("code")
        except ValueError:
            code = "<non-JSON body>"
    ok = status == want_status and (want_code is None or code == want_code)
    failures += not ok
    print(("ok  " if ok else "FAIL"), f"{name}: {status} {code or ''}".rstrip(),
          "" if ok else f"(want {want_status} {want_code or ''}; body {raw[:200]!r})")


check("healthz", "GET", "/healthz", None, 200, ctype=None)
check("metrics", "GET", "/metrics", None, 200, ctype=None)

# Structural checks only: every request gets a fresh issued_at and nonce, so
# freshness entries (expired, replayed) are exercised by e2e_corpus.py instead.
fresh = lambda r: json.dumps(Templater().render(r)).encode()
requests = {f: fresh(json.load(open(f))) for f in sorted(glob.glob("spec/fixtures/action_request.*.json"))}
for f in sorted(glob.glob("corpus/attacks/*.yaml")):
    entry = yaml.safe_load(open(f))
    for i, r in enumerate(entry.get("requests") or [entry["request"]]):
        requests[f if "request" in entry else f"{f}#{i}"] = fresh(r)
for name, body in requests.items():
    check(f"valid request passes gateway: {name}", "POST", "/v1/evaluate", body, 503, "ENGINE_UNAVAILABLE")

evm = json.dumps(json.load(open("spec/fixtures/action_request.evm_tx.json"))).encode()  # structure only: fails before freshness
check("wrong method", "GET", "/v1/evaluate", None, 405, "METHOD_NOT_ALLOWED", ctype=None)
check("unknown route", "GET", "/v1/nope", None, 404, "NOT_FOUND", ctype=None)
check("wrong content type", "POST", "/v1/evaluate", evm, 415, "UNSUPPORTED_MEDIA_TYPE", ctype="text/plain")
check("body too large", "POST", "/v1/evaluate", b" " * (64 * 1024 + 1), 413, "BODY_TOO_LARGE")
check("malformed json", "POST", "/v1/evaluate", b"{", 400, "MALFORMED_JSON")
check("duplicate key", "POST", "/v1/evaluate", b'{"id":"a","id":"b"}', 400, "DUPLICATE_KEY")
check("case-variant key smuggling", "POST", "/v1/evaluate",
      evm.replace(b'"to":', b'"To":"0x9f30000000000000000000000000000000000c21","to":', 1), 400, "UNKNOWN_FIELD")
check("integer beyond 2^53", "POST", "/v1/evaluate", evm.replace(b'"chain_id": 8453', b'"chain_id": 9007199254740993', 1), 400, "NUMBER_PRECISION")
check("fails validation", "POST", "/v1/evaluate", evm.replace(b'"value_wei": "0"', b'"value_wei": "-1"', 1), 400, "INVALID_REQUEST")

status, raw = call("GET", "/metrics", ctype=None)
for want in [b'stopbar_gateway_rejections_total{code="ENGINE_UNAVAILABLE"} ' + str(len(requests)).encode(),
             b'stopbar_gateway_rejections_total{code="DUPLICATE_KEY"} 1']:
    ok = want in raw
    failures += not ok
    print("ok  " if ok else "FAIL", "metrics:", want.decode())

sys.exit(failures)
