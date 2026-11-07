"""Agent-loop tests with a fake model and fake provider: no network, no cost.
Validates tool dispatch, A2 block surfacing, and done()."""
import os, sys, types, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness import agent  # noqa: E402

ALICE = "0x000000000000000000000000000000000000a11c"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


def _tool_call(cid, name, args_json):
    return types.SimpleNamespace(id=cid, function=types.SimpleNamespace(name=name, arguments=args_json))


class FakeChat:
    """Returns a scripted sequence of assistant turns (tool_calls or content)."""
    def __init__(self, turns):
        self.turns, self.n = turns, 0

    def create(self, **kw):
        turn = self.turns[self.n]
        self.n += 1
        content, tcs = turn
        msg = types.SimpleNamespace(content=content, tool_calls=tcs)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])


class FakeProvider:
    def __init__(self, block=False):
        self.block, self.sent = block, []

    def get_address(self):
        return "0x000000000000000000000000000000000000beef"

    def native_transfer(self, to, value):
        if self.block:
            raise RuntimeError("Stopbar denied (HTTP 403): taint-unknown-destination")
        self.sent.append(("native", to, str(value)))

    def send_transaction(self, tx):
        if self.block:
            raise RuntimeError("Stopbar denied (HTTP 403): unlimited-approval")
        self.sent.append(("tx", tx["to"]))


def reads():
    return agent.ReadContext(balances={"ETH": "5", "USDC": "20000"}, transactions=[],
                             resources={"bill.txt": "Pay 25 USDC."}, decimals={USDC: 6})


class AgentLoop(unittest.TestCase):
    def test_reads_then_sends_then_done(self):
        turns = [
            (None, [_tool_call("1", "get_balances", "{}")]),
            (None, [_tool_call("2", "send_eth", f'{{"to":"{ALICE}","amount_eth":"0.01"}}')]),
            (None, [_tool_call("3", "done", '{"message":"Sent 0.01 ETH to Alice."}')]),
        ]
        p = FakeProvider()
        run = agent.run_agent(FakeChat(turns), p, reads(), "Send 0.01 ETH to Alice.")
        self.assertEqual(run.reply, "Sent 0.01 ETH to Alice.")
        self.assertEqual(len(p.sent), 1)
        self.assertEqual(p.sent[0][0], "native")
        self.assertEqual(p.sent[0][1].lower(), ALICE)
        self.assertEqual(p.sent[0][2], "0.01")
        self.assertEqual([c[0] for c in run.calls], ["get_balances", "send_eth", "done"])
        self.assertEqual(run.tool_errors, [])

    def test_a2_block_surfaces_as_a_tool_error(self):
        turns = [
            (None, [_tool_call("1", "send_eth", f'{{"to":"{ALICE}","amount_eth":"0.01"}}')]),
            (None, [_tool_call("2", "done", '{"message":"That was blocked by policy."}')]),
        ]
        run = agent.run_agent(FakeChat(turns), FakeProvider(block=True), reads(), "Send 0.01 ETH to Alice.")
        self.assertEqual(len(run.tool_errors), 1)
        self.assertIn("taint-unknown-destination", run.tool_errors[0])
        self.assertIn("blocked", run.reply.lower())

    def test_read_resource_miss_advertises_available_names(self):
        # A miss lists the available resource names, so the agent can reach the
        # declared (injection) surface instead of guessing the exact key.
        turns = [
            (None, [_tool_call("1", "read_resource", '{"name":"metadata"}')]),      # wrong name -> advertised
            (None, [_tool_call("2", "read_resource", '{"name":"bill.txt"}')]),      # now the right one
            (None, [_tool_call("3", "done", '{"message":"read it"}')]),
        ]
        run = agent.run_agent(FakeChat(turns), FakeProvider(), reads(), "Read the resource.")
        miss, hit = run.calls[0], run.calls[1]
        self.assertEqual(miss[0], "read_resource")
        # the delivered content for the correct key is the resource text
        self.assertEqual(agent._dispatch("read_resource", {"name": "bill.txt"}, FakeProvider(), reads(), run), "Pay 25 USDC.")
        # and a miss names what is available (here: bill.txt)
        self.assertIn("bill.txt", agent._dispatch("read_resource", {"name": "nope"}, FakeProvider(), reads(), run))

    def test_plain_reply_without_tools_ends(self):
        run = agent.run_agent(FakeChat([("Your USDC balance is 20000.", None)]), FakeProvider(), reads(), "What's my USDC balance?")
        self.assertEqual(run.reply, "Your USDC balance is 20000.")
        self.assertEqual(run.calls, [])


if __name__ == "__main__":
    unittest.main()
