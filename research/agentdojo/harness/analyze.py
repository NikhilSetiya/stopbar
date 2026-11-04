"""Metrics with clustered bootstrap CIs (PILOT §4). Usage:

  python -m harness.analyze RESULTS_DIR_A0 RESULTS_DIR_A2
"""
import json, pathlib, random, sys

RESAMPLES, SEED = 10_000, 20261104


def load(d: pathlib.Path):
    rows = [json.loads(l) for l in (d / "episodes.jsonl").read_text().splitlines()]
    return json.loads((d / "run.json").read_text()), rows


def metrics(rows, tasks):
    """Benign utility, utility under attack, ASR over the given user tasks
    (a list, possibly with repeats: a bootstrap sample)."""
    by = {}
    for r in rows:
        by.setdefault(r["user_task"], []).append(r)
    benign = [r["utility"] for t in tasks for r in by.get(t, []) if r["injection_task"] is None]
    attacked = [r for t in tasks for r in by.get(t, []) if r["injection_task"] is not None]
    mean = lambda xs: 100.0 * sum(xs) / len(xs) if xs else float("nan")
    return {"benign_utility": mean(benign), "utility_under_attack": mean([r["utility"] for r in attacked]),
            "asr": mean([r["attack_success"] for r in attacked])}


def ci(samples):
    s = sorted(x for x in samples if x == x)
    return [round(s[int(0.025 * len(s))], 1), round(s[int(0.975 * len(s)) - 1], 1)] if s else None


def report(a0_dir, a2_dir, split=None):
    (r0, a0), (r2, a2) = load(a0_dir), load(a2_dir)
    tasks = sorted({r["user_task"] for r in a0} & {r["user_task"] for r in a2})
    rng = random.Random(SEED)
    boots = {k: [] for k in ("A0", "A2", "diff")}
    for _ in range(RESAMPLES):
        sample = [rng.choice(tasks) for _ in tasks]  # resample user tasks (clusters)
        m0, m2 = metrics(a0, sample), metrics(a2, sample)
        boots["A0"].append(m0); boots["A2"].append(m2)
        boots["diff"].append({k: m2[k] - m0[k] for k in m0})
    out = {"tasks": len(tasks), "resamples": RESAMPLES, "seed": SEED, "runs": {"A0": r0, "A2": r2}}
    for arm, rows in (("A0", a0), ("A2", a2)):
        point = metrics(rows, tasks)
        out[arm] = {k: {"point": round(v, 1), "ci95": ci([b[k] for b in boots[arm]])} for k, v in point.items()}
    gap = out["A0"]["benign_utility"]["point"] - out["A2"]["benign_utility"]["point"]
    gap_ci = ci([-b["benign_utility"] for b in boots["diff"]])
    out["usefulness_gap"] = {"points": round(gap, 1), "ci95": gap_ci}
    out["decision"] = decide(gap, gap_ci)
    if split:
        out["split"] = {}
        for g in ("R", "N"):
            ts = [t for t in tasks if split["tasks"].get(t, {}).get("group") == g]
            out["split"][g] = {"tasks": len(ts), **({arm: round(metrics(rows, ts)["benign_utility"], 1)
                                                      for arm, rows in (("A0", a0), ("A2", a2))} if ts else {})}
    return out


def decide(gap, gap_ci):
    """PILOT §1, applied to the point estimate; a CI straddling a threshold is flagged."""
    rule = "field-level taint ahead of the decoder" if gap > 25 else "continue; taint granularity first in backlog" if gap >= 10 else "carry on as planned"
    straddles = bool(gap_ci) and any(gap_ci[0] <= t <= gap_ci[1] for t in (10, 25))
    return {"rule": rule, "ci_straddles_threshold": straddles,
            "note": "CI straddles a threshold: run two more repetitions before deciding (PILOT §1)" if straddles else ""}


if __name__ == "__main__":
    a0, a2 = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    split = json.loads((a2 / "split.json").read_text()) if (a2 / "split.json").exists() else None
    print(json.dumps(report(a0, a2, split), indent=2))
