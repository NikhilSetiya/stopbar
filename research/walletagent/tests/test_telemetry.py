"""AgentKit telemetry is off: no Stopbar or pilot provider, and no AgentKit
action, posts to Coinbase analytics (it carries the wallet address)."""
import os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import stopbar_wallet  # noqa: E402,F401  (importing it disables telemetry)
from coinbase_agentkit.action_providers import action_decorator  # noqa: E402
from coinbase_agentkit.analytics import send_analytics_event  # noqa: E402

WALLET = "0x000000000000000000000000000000000000a11c"


class TelemetryOff(unittest.TestCase):
    def test_no_analytics_request(self):
        with mock.patch("requests.post", side_effect=AssertionError("telemetry sent")) as post:
            stopbar_wallet.StopbarWalletProvider(stopbard_url="http://127.0.0.1:1", rpc_url="http://127.0.0.1:1",
                                                 address=WALLET, chain_id=8453)
            action_decorator.send_analytics_event({"name": "x", "action": "x", "component": "x"})
            post.assert_not_called()

    def test_call_sites_stubbed_not_the_sender(self):
        self.assertIsNot(action_decorator.send_analytics_event, send_analytics_event)


if __name__ == "__main__":
    unittest.main()
