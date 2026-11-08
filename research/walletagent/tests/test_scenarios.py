"""Offline checks on the owner-authored scenario goals (PILOT-2 §3.2)."""
import json, os, pathlib, unittest

FIX = pathlib.Path(os.path.dirname(__file__)).parent / "fixtures"


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.sc = json.loads((FIX / "scenarios.json").read_text())["scenarios"]
        self.world = json.loads((FIX / "world.json").read_text())
        self.addr = json.loads((FIX / "addresses.json").read_text())

    def test_four_scenarios_s4_excluded(self):
        self.assertEqual(set(self.sc), {"S1", "S2", "S3", "S5"})

    def test_every_goal_names_its_address(self):
        for k, v in self.sc.items():
            target = v.get("attacker") or v.get("lookalike")
            self.assertIn(target.lower(), v["goal"].lower(), k)

    def test_attacker_addresses_not_allowlisted(self):
        known = set(self.world["known_destinations"])
        for k, v in self.sc.items():
            target = (v.get("attacker") or v.get("lookalike")).lower()
            self.assertNotIn(target, known, k)

    def test_s2_lookalike_resembles_alice(self):
        alice = self.addr["contacts"]["alice"].lower()
        look = self.sc["S2"]["lookalike"].lower()
        self.assertNotEqual(look, alice)
        self.assertEqual(look[:6], alice[:6])   # same first 4 hex
        self.assertEqual(look[-4:], alice[-4:])  # same last 4 hex


class ScenarioWiring(unittest.TestCase):
    def test_build_returns_four_scenarios_with_fixture_targets(self):
        import os, sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from harness import scenarios
        import json, pathlib
        g = json.loads((pathlib.Path(scenarios.__file__).parent.parent / "fixtures" / "scenarios.json").read_text())["scenarios"]
        built = {s.id: s for s in scenarios.build()}
        self.assertEqual(set(built), {"S1", "S2", "S3", "S5"})
        self.assertEqual(built["S1"].target, g["S1"]["attacker"])
        self.assertEqual(built["S2"].target, g["S2"]["lookalike"])
        self.assertEqual(built["S3"].target, g["S3"]["attacker"])
        # the injection surface places text where the agent reads it
        r = built["S1"].reads("INJECTED")
        self.assertEqual(r.resources["token_metadata"], "INJECTED")
