"""Orchestration control-flow tests (PILOT-2 Amendment A5): gates, sub-caps,
hard stops, resume. Stubbed episode runners — no fork, no model, no cost."""
import os, sys, tempfile, unittest
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness import stages  # noqa: E402


@dataclass
class T:
    id: str


@dataclass
class Sc:
    id: str


TASKS = [T(f"t{i}") for i in range(20)]
SCEN = [Sc("S1"), Sc("S2"), Sc("S3"), Sc("S5")]


def _run(benign_fn, attack_fn, usd_fn=lambda: 0.0, resume_dir=None):
    d = resume_dir or Path(tempfile.mkdtemp())
    prog = stages.Progress(d / "progress.jsonl")
    res = stages.run_stages(benign_fn=benign_fn, attack_fn=attack_fn, usd_fn=usd_fn,
                            benign_tasks=TASKS, scenarios=SCEN, progress=prog, out=d)
    return res, d


class Gates(unittest.TestCase):
    def test_stage1_gate_fail_stops_before_stage2(self):
        seen = {"attack": 0}
        res, _ = _run(benign_fn=lambda *a: a[-1].id in {f"t{i}" for i in range(14)},  # 14/20 < 15
                      attack_fn=lambda *a: seen.__setitem__("attack", seen["attack"] + 1))
        self.assertEqual(res["stopped"]["reason"], "stage1_gate_failed")
        self.assertNotIn("stage2", res["stages"])
        self.assertEqual(seen["attack"], 0)  # never ran attacked

    def test_stage2_gate_fail_stops_before_stage3(self):
        res, _ = _run(benign_fn=lambda *a: True,                 # 20/20 passes stage 1
                      attack_fn=lambda stage, arm, sc, i: sc.id == "S1" and i < 3)  # 3 successes, 1 scenario
        self.assertEqual(res["stages"]["stage1"]["a0_benign_passed"], 20)
        self.assertEqual(res["stopped"]["reason"], "stage2_gate_failed")
        self.assertNotIn("stage3", res["stages"])

    def test_full_pass_reaches_stage3(self):
        # 20/20 benign; 5 successes across 2 scenarios passes stage 2.
        def attack(stage, arm, sc, i):
            return (sc.id == "S1" and i < 3) or (sc.id == "S5" and i < 2)
        res, _ = _run(benign_fn=lambda *a: True, attack_fn=attack)
        self.assertIsNone(res["stopped"])
        self.assertIn("stage3", res["stages"])
        self.assertEqual(res["stages"]["stage2"]["a0_successes"], 5)
        self.assertEqual(res["stages"]["stage2"]["scenarios"], ["S1", "S5"])

    def test_subcap_stop_is_terminal(self):
        res, _ = _run(benign_fn=lambda *a: True, attack_fn=lambda *a: False, usd_fn=lambda: 9.99)
        self.assertEqual(res["stopped"]["reason"], "cap_exceeded")

    def test_hard_stop_from_episode_propagates(self):
        def benign(stage, arm, task):
            raise stages.Stop("model_mismatch", "reported != pinned")
        res, _ = _run(benign_fn=benign, attack_fn=lambda *a: False)
        self.assertEqual(res["stopped"]["reason"], "model_mismatch")

    def test_resume_skips_finished_episodes(self):
        calls = {"n": 0}

        def benign(stage, arm, task):
            calls["n"] += 1
            return True
        # First run fails stage 2 (records all stage-1 benign + stage-2 attacks).
        _, d = _run(benign_fn=benign, attack_fn=lambda *a: False)
        first = calls["n"]
        self.assertEqual(first, 20)  # stage 1 benign ran once
        # Resume in the same dir: stage-1 benign are already recorded, not re-run.
        _run(benign_fn=benign, attack_fn=lambda *a: False, resume_dir=d)
        self.assertEqual(calls["n"], first)  # no benign re-run on resume


if __name__ == "__main__":
    unittest.main()
