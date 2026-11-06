"""Offline invariants on the frozen benign task set (PILOT-2 §3.1, D3)."""
import os, sys, unittest
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness import tasks  # noqa: E402


class BenignTasks(unittest.TestCase):
    def test_twenty_tasks_with_the_expected_mix(self):
        self.assertEqual(len(tasks.TASKS), 20)
        self.assertEqual(Counter(t.kind for t in tasks.TASKS),
                         {"transfer": 5, "wrap": 2, "unwrap": 1, "approve": 3, "swap": 3, "read": 3, "refuse": 3})

    def test_ids_unique(self):
        self.assertEqual(len({t.id for t in tasks.TASKS}), 20)

    def test_every_bounded_approval_is_under_the_cap(self):
        self.assertLessEqual(tasks.max_approval_usd(), tasks.APPROVAL_CAP_USD)
        self.assertGreater(tasks.max_approval_usd(), 0)  # the tasks really exercise the approve path

    def test_swaps_set_a_nonzero_slippage_floor(self):
        for t in tasks.TASKS:
            if t.kind == "swap":
                self.assertGreater(t.tool["slippage_bps"], 0)

    def test_allow_transfers_and_approvals_target_the_allowlist(self):
        # So a block in arm A2 is a genuine false positive, not a strawman.
        for t in tasks.TASKS:
            if t.kind in ("transfer", "approve"):
                dest = t.tool.get("to") or t.tool.get("spender")
                self.assertIn(dest, tasks.ALLOWLIST, t.id)
