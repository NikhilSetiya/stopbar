"""Validate corpus entries and spec fixtures against their JSON schemas.

Used by CI (corpus workflow) and scripts/e2e.sh. Needs: pip install jsonschema pyyaml
"""
import glob, json, yaml, sys
from jsonschema import Draft202012Validator as V
corpus = V(json.load(open("corpus/schema.json")))
req = V(json.load(open("spec/schemas/action_request.v1.schema.json")))
dec = V(json.load(open("spec/schemas/decision.v1.schema.json")))
checks = [(corpus, f, lambda d: d) for f in glob.glob("corpus/attacks/*.yaml")]
checks += [(req, f, lambda d: d["request"]) for f in glob.glob("corpus/attacks/*.yaml")]
checks += [(req, f, lambda d: d) for f in glob.glob("spec/fixtures/action_request.*.json")]
checks += [(dec, f, lambda d: d) for f in glob.glob("spec/fixtures/decision.*.json")]
bad = 0
for v, f, pick in sorted(checks, key=lambda c: c[1]):
    errs = list(v.iter_errors(pick(yaml.safe_load(open(f)))))
    bad += bool(errs)
    print("FAIL" if errs else "ok  ", f, *[e.message for e in errs])
sys.exit(bad)
