"""Metered-client tests: no network, no cost (fake OpenAI client)."""
import os, sys, types, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import openai  # noqa: E402

from harness import spend  # noqa: E402

VICTIM = "deepseek-ai/DeepSeek-V4.1-Flash-1017"


def usage(pin, pout):
    return types.SimpleNamespace(prompt_tokens=pin, completion_tokens=pout)


def resp(model=VICTIM, pin=1000, pout=100):
    return types.SimpleNamespace(model=model, usage=usage(pin, pout),
                                 choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="ok", tool_calls=None))])


def status_error(code):
    req = openai.OpenAI(api_key="x").chat.completions  # any; only for the exception shape
    import httpx
    r = httpx.Response(code, request=httpx.Request("POST", "https://api.together.xyz/v1/chat/completions"))
    return openai.APIStatusError("boom", response=r, body=None)


class FakeCompletions:
    def __init__(self, script):
        self.script, self.n = list(script), 0

    def create(self, **kw):
        self.n += 1
        x = self.script.pop(0)
        if isinstance(x, Exception):
            raise x
        return x


class FakeClient:
    def __init__(self, *script):
        self.chat = types.SimpleNamespace(completions=FakeCompletions(script))


class SpendMeter(unittest.TestCase):
    def setUp(self):
        for t in ("time.sleep", "random.uniform"):
            p = mock.patch(f"harness.spend.{t}", **({"return_value": 0} if "uniform" in t else {}))
            p.start(); self.addCleanup(p.stop)

    def chat(self, *script, cap=5.0, attempts=10, model=VICTIM):
        m = spend.Meter(cap_usd=cap, max_attempts=attempts)
        return spend.MeteredChat(FakeClient(*script), model, m), m

    def test_transient_statuses_are_retried_then_succeed(self):
        c, m = self.chat(status_error(429), status_error(503), resp())
        self.assertEqual(c.create(messages=[]).model, VICTIM)
        self.assertEqual(sum(m.retries.values()), 2)
        self.assertEqual(m.calls[VICTIM], 1)

    def test_non_transient_status_is_not_retried(self):
        c, m = self.chat(status_error(400))
        with self.assertRaises(openai.APIStatusError):
            c.create(messages=[])
        self.assertEqual(m.calls.get(VICTIM, 0), 0)

    def test_spend_cap_aborts_and_latches(self):
        c, m = self.chat(resp(pin=20_000_000), resp(), cap=2.0)  # 20M in * $0.30/M = $6 > $2
        with self.assertRaises(spend.SpendCapExceeded):
            c.create(messages=[])
        with self.assertRaises(spend.SpendCapExceeded):
            c.create(messages=[])
        self.assertEqual(c.client.chat.completions.n, 1)  # no call after the cap

    def test_model_mismatch_aborts(self):
        c, m = self.chat(resp(model="deepseek-ai/DeepSeek-V4.1-Flash"))  # alias drifted off the dated pin
        with self.assertRaises(spend.ModelMismatch):
            c.create(messages=[])

    def test_unpriced_model_is_rejected(self):
        with self.assertRaises(SystemExit):
            spend.MeteredChat(FakeClient(), "some/unpinned-model", spend.Meter(cap_usd=5.0))

    def test_retries_run_out_into_an_abort(self):
        c, m = self.chat(*[status_error(503)] * 3, attempts=3)
        with self.assertRaises(spend.Abort):
            c.create(messages=[])

    def test_cost_is_summed_per_model_at_pinned_prices(self):
        c, m = self.chat(resp(pin=1_000_000, pout=1_000_000))
        c.create(messages=[])
        self.assertAlmostEqual(m.usd, 0.30 + 1.20, places=6)  # DeepSeek: $0.30 in + $1.20 out


if __name__ == "__main__":
    unittest.main()
