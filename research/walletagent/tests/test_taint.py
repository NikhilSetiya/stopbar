"""Trust map + monotonic session taint (PILOT-2 harness v1.1). No network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness import taint  # noqa: E402


class TrustMap(unittest.TestCase):
    def test_trust_file_is_the_bundle_tool_trust_json(self):
        self.assertEqual(taint.TRUST_FILE.name, "tool-trust.json")
        self.assertTrue(taint.TRUST_FILE.exists())

    def test_untrusted_output_tools_are_the_two_read_surfaces(self):
        t = taint.load_trust()
        self.assertEqual(set(t["untrusted_output_tools"]), {"get_recent_transactions", "read_resource"})
        # every untrusted tool is a declared read-only tool (decided from definitions)
        for tool in t["untrusted_output_tools"]:
            self.assertIn(tool, t["read_only_tools"])


class Taint(unittest.TestCase):
    def test_session_starts_trusted_and_is_monotonic(self):
        s = taint.Session()
        self.assertEqual(s.provenance(), ["trusted_user"])
        s.taint_tool("read_resource", "untrusted_web")
        s.taint_tool("read_resource", "untrusted_web")  # idempotent
        s.taint_tool("get_recent_transactions", "untrusted_onchain")
        self.assertEqual(s.provenance(), ["trusted_user", "untrusted_onchain", "untrusted_web"])

    def test_only_untrusted_output_tools_taint(self):
        s = taint.Session()
        s.taint_tool("get_balances", "untrusted_web")   # trusted read: ignored
        s.taint_tool("get_allowance", "untrusted_onchain")
        s.taint_tool("read_resource", "")               # no label: ignored
        self.assertEqual(s.provenance(), ["trusted_user"])

    def test_reset_clears_taint_between_episodes(self):
        s = taint.Session()
        s.taint_tool("read_resource", "untrusted_email")
        self.assertIn("untrusted_email", s.provenance())
        s.reset()
        self.assertEqual(s.provenance(), ["trusted_user"])


if __name__ == "__main__":
    unittest.main()
