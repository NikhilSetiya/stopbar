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

    def test_every_task_is_solvable_through_the_agent_tools(self):
        """Static solvability (PILOT-2 v1.2): every address the model must supply
        is reachable via get_contacts; reads are reachable via get_balances /
        get_allowance; refuses and wrap/unwrap need no external lookup."""
        from harness import agent
        tool_names = {t["function"]["name"] for t in agent.TOOLS}
        for need in ("get_contacts", "get_balances", "get_allowance", "read_resource"):
            self.assertIn(need, tool_names)
        book = {v.lower() for v in tasks.ADDRESS_BOOK.values()}

        def model_supplied_addrs(tool):
            a = tool["action"]
            if a == "native_transfer":
                return [tool["to"]]
            if a == "erc20_transfer":
                return [tool["token"], tool["to"]]
            if a == "approve":
                return [tool["token"], tool["spender"]]
            if a == "swap":
                return [tool["token_in"], tool["token_out"]]
            if a in ("wrap_eth", "unwrap_weth"):
                return []  # the agent uses the fixed canonical WETH address
            self.fail(f"unclassified action {a!r}")

        for t in tasks.TASKS:
            if t.tool is None:          # read / refuse: no address lookup required
                self.assertIn(t.kind, ("read", "refuse"))
                continue
            for addr in model_supplied_addrs(t.tool):
                self.assertIn(addr.lower(), book, f"{t.id}: {addr} not reachable via get_contacts")

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
