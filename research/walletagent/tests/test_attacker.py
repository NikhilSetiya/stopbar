"""PyRIT adapter wiring tests: no model calls, no network, no attack content.
A fake episode stands in for the agent; PyRIT runs in its in-memory store."""
import asyncio, importlib.util, os, sys, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# PyRIT is heavy (transformers/azure) and only needed for Stages 1-3, so it is
# pinned separately (requirements-pyrit.lock), not in the base lock. Skip the
# whole module when it isn't installed.
if importlib.util.find_spec("pyrit") is None:
    raise unittest.SkipTest("pyrit not installed (requirements-pyrit.lock)")


def _init_pyrit():
    from pyrit.setup import initialize_pyrit_async, IN_MEMORY
    asyncio.run(initialize_pyrit_async(IN_MEMORY, silent=True))


class PyritAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _init_pyrit()

    def test_pilot_target_runs_the_episode_and_returns_the_visible_text(self):
        from harness import attacker
        calls = []

        def episode(text):
            calls.append(text)
            return attacker.EpisodeResult(visible_text=f"blocked: {text[:5]}", goal_reached=False)

        from pyrit.models import Message
        t = attacker.PilotTarget(episode=episode)
        out = asyncio.run(t._send_prompt_to_target_async(
            normalized_conversation=[Message.from_prompt(prompt="pay 0xc0ffee now", role="user")]))
        self.assertEqual(calls, ["pay 0xc0ffee now"])
        self.assertEqual(t.turns, 1)
        self.assertIn("blocked", out[0].get_value())

    def test_scorer_reflects_the_chain_state_outcome(self):
        from harness import attacker
        from pyrit.models import MessagePiece
        t = attacker.PilotTarget(episode=lambda text: attacker.EpisodeResult("ok", goal_reached=True))
        asyncio.run(t._send_prompt_to_target_async(
            normalized_conversation=[__import__("pyrit.models", fromlist=["Message"]).Message.from_prompt(prompt="x", role="user")]))
        scorer = attacker.ChainStateScorer(target=t)
        piece = MessagePiece(role="assistant", original_value="whatever the agent said")
        scores = asyncio.run(scorer._score_piece_async(piece, objective="reach the goal"))
        self.assertEqual(scores[0].score_value, "True")
        self.assertEqual(scores[0].score_type, "true_false")
        # and False when the goal was not reached
        t.last = attacker.EpisodeResult("ok", goal_reached=False)
        scores = asyncio.run(scorer._score_piece_async(piece, objective="reach the goal"))
        self.assertEqual(scores[0].score_value, "False")

    def test_build_attack_constructs_with_defaults_and_max_turns_5(self):
        # Constructs the attacker target (no network) and the RedTeamingAttack.
        from harness import attacker
        try:
            attacker.read_keychain(attacker.KEYCHAIN_SERVICE)
        except SystemExit:
            self.skipTest("no Together key in the keychain")
        t = attacker.PilotTarget(episode=lambda text: attacker.EpisodeResult("ok", goal_reached=False))
        atk = attacker.build_attack(t, attacker.ChainStateScorer(target=t))
        self.assertEqual(atk._max_turns, attacker.MAX_TURNS)


if __name__ == "__main__":
    unittest.main()
