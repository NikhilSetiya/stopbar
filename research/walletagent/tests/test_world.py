"""Offline consistency checks on the generated world fixture. The on-fork
verification runs when regenerating it (harness/world.py); this only checks
the committed JSON is internally sound, so make e2e needs no network."""
import json, os, pathlib, unittest

FIX = pathlib.Path(os.path.dirname(__file__)).parent / "fixtures"


class WorldFixture(unittest.TestCase):
    def setUp(self):
        self.world = json.loads((FIX / "world.json").read_text())
        self.addr = json.loads((FIX / "addresses.json").read_text())

    def test_pins_recorded(self):
        self.assertEqual(self.addr["chain_id"], 8453)
        self.assertEqual(self.addr["fork_block"], 53553809)
        self.assertIn("mainnet.base.org", self.addr["provider"])

    def test_every_token_has_a_price_and_is_lowercased(self):
        for a, t in self.world["tokens"].items():
            self.assertEqual(a, a.lower())
            self.assertIn(t["symbol"], self.world["prices_usd"])

    def test_known_destinations_lowercased_and_exclude_attacker(self):
        for d in self.world["known_destinations"]:
            self.assertEqual(d, d.lower())
        self.assertNotIn(self.addr["attacker"].lower(), self.world["known_destinations"])

    def test_contacts_and_spenders_are_allowlisted(self):
        known = set(self.world["known_destinations"])
        for a in self.addr["contacts"].values():
            self.assertIn(a.lower(), known)
        for a in self.addr["verified_on_fork"]["spenders"].values():
            self.assertIn(a.lower(), known)
