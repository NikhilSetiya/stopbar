"""Harness unit tests (no API, no stopbard needed). Run from research/agentdojo:
  .venv/bin/python -m unittest discover -s tests"""
import json, pathlib, tempfile, unittest
from unittest import mock

from google.genai import types as T
from google.genai.errors import ClientError, ServerError

import anthropic, asyncio, httpx

from harness import analyze, gate, gemini, infra, llm, pins


class DecisionRule(unittest.TestCase):
    def test_thresholds_match_pilot_section_1(self):
        self.assertIn("field-level", analyze.decide(25.1, [20, 30])["rule"])
        self.assertIn("taint granularity", analyze.decide(25.0, [20, 30])["rule"])
        self.assertIn("taint granularity", analyze.decide(10.0, [9, 11])["rule"])
        self.assertIn("carry on", analyze.decide(9.9, [5, 9.95])["rule"])

    def test_straddling_ci_is_flagged(self):
        self.assertTrue(analyze.decide(30, [20, 40])["ci_straddles_threshold"])
        self.assertFalse(analyze.decide(40, [30, 50])["ci_straddles_threshold"])


class Bootstrap(unittest.TestCase):
    def _write(self, d, rows):
        d.mkdir()
        (d / "episodes.jsonl").write_text("\n".join(json.dumps(r) for r in rows))

    def test_deterministic_and_clustered(self):
        a0 = [{"user_task": f"t{i}", "injection_task": None, "utility": True} for i in range(10)]
        a2 = [{"user_task": f"t{i}", "injection_task": None, "utility": i < 4} for i in range(10)]
        for rows in (a0, a2):
            rows += [{"user_task": r["user_task"], "injection_task": "x", "utility": r["utility"], "attack_success": False} for r in list(rows)]
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            (t / "run.json").write_text("{}")
            (t / "progress.jsonl").write_text("".join(json.dumps({"user_task": f"t{i}"}) + "\n" for i in range(10)))
            self._write(t / "A0", a0)
            self._write(t / "A2", a2)
            r1, r2 = analyze.report(t), analyze.report(t)
        self.assertEqual(r1["usefulness_gap"], r2["usefulness_gap"])  # fixed seed
        self.assertEqual(r1["usefulness_gap"]["points"], 60.0)
        lo, hi = r1["usefulness_gap"]["ci95"]
        self.assertTrue(lo <= 60.0 <= hi)


class GateFailsClosed(unittest.TestCase):
    def test_unreachable_stopbard_blocks(self):
        status, d = gate.evaluate("http://127.0.0.1:9", "s", "send_money", {}, timeout=1)
        self.assertEqual(status, 0)
        self.assertEqual(d["code"], "GATE_UNREACHABLE")


class Pins(unittest.TestCase):
    def test_frozen_hash_comes_from_freeze_md(self):
        self.assertRegex(pins.frozen_bundle_hash(), r"^sha256:[0-9a-f]{64}$")

    def test_models_are_the_pre_registered_ones(self):
        self.assertEqual(set(pins.MODELS), {"gemini-3.8-flash", "claude-haiku-4-5", "claude-opus-5-5"})
        self.assertEqual(pins.PILOT_MODEL, "claude-haiku-4-5")  # Amendment 4 not taken


class _Resp:
    def __init__(self, tier, model="gemini-3.8-flash"):
        self.sdk_http_response = type("H", (), {"headers": {gemini.TIER_HEADER: tier}})()
        self.model_version, self.usage_metadata = model, None


def _err429(*quota_ids, delay="0s"):
    return ClientError(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "details": [
        {"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [{"quotaId": q} for q in quota_ids]},
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": delay}]}})


class _Inner:
    def __init__(self, *script):
        self.script, self.n = list(script), 0

    def generate_content(self, **kw):
        self.n += 1
        x = self.script.pop(0)
        if isinstance(x, Exception):
            raise x
        return x


class _NoSleep(unittest.TestCase):
    def setUp(self):  # no real backoff in tests
        for target in ("harness.gemini.time.sleep", "harness.infra.random.uniform", "harness.llm.asyncio.sleep"):
            p = mock.patch(target, new=mock.AsyncMock() if "asyncio" in target else mock.Mock(return_value=0))
            p.start()
            self.addCleanup(p.stop)


class GeminiGuard(_NoSleep):
    def models(self, *script, attempts=12):
        g = gemini.Guard("gemini-3.8-flash", infra.Infra(max_attempts=attempts))
        return gemini._Models(_Inner(*script), g), g

    def test_per_minute_429_and_5xx_are_retried_not_results(self):
        m, g = self.models(_err429("GenerateRequestsPerMinutePerProjectPerModel-FreeTier"),
                           ServerError(503, {"error": {"code": 503}}), _Resp("standard"))
        self.assertEqual(m.generate_content(model="x").model_version, "gemini-3.8-flash")
        self.assertEqual((g.infra.retries, g.calls), ({"429": 1, "5xx_or_network": 1}, 1))
        self.assertEqual(g.tiers, {"standard"})  # recorded, not enforced: it isn't a billing signal

    def test_daily_quota_stops_the_run_and_is_not_a_server_error(self):
        m, g = self.models(_err429("GenerateRequestsPerDayPerProjectPerModel-FreeTier"))
        with self.assertRaises(infra.InfraAbort) as cm:
            m.generate_content(model="x")
        self.assertNotIsInstance(cm.exception, ServerError)  # AgentDojo scores ServerError as a failed task
        with self.assertRaises(infra.InfraAbort):
            m.generate_content(model="x")
        self.assertEqual(m.inner.n, 1)  # no request after the stop

    def test_non_free_quota_429_aborts(self):
        m, _ = self.models(_err429("GenerateRequestsPerMinutePerProjectPerModel"))
        with self.assertRaises(gemini.BilledTier):
            m.generate_content(model="x")

    def test_reported_model_must_equal_pin(self):
        m, _ = self.models(_Resp("standard", model="gemini-3.9-flash"))  # the API reroutes some IDs
        with self.assertRaises(infra.InfraAbort):
            m.generate_content(model="x")

    def test_retries_run_out_into_an_abort(self):
        m, _ = self.models(*[ServerError(503, {"error": {"code": 503}})] * 3, attempts=3)
        with self.assertRaises(infra.InfraAbort):
            m.generate_content(model="x")


def _api_err(cls, status, headers=None):
    r = httpx.Response(status, headers=headers or {}, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
    return cls("err", response=r, body=None)


class _Msg:
    def __init__(self, model="claude-haiku-4-5", inp=1000, out=100):
        self.model = model
        self.usage = type("U", (), {"input_tokens": inp, "output_tokens": out})()


class _AStream:
    def __init__(self, x):
        self.x = x

    async def __aenter__(self):
        if isinstance(self.x, Exception):
            raise self.x
        return self

    async def __aexit__(self, *a):
        return False

    async def get_final_message(self):
        return self.x


class _AMessages:
    def __init__(self, *script):
        self.script, self.n = list(script), 0

    def stream(self, **kw):
        self.n += 1
        return _AStream(self.script.pop(0))


class AnthropicInfra(_NoSleep):
    def client(self, *script, cap=20.0, attempts=12):
        meter = llm.Meter("claude-haiku-4-5", cap, infra.Infra(max_attempts=attempts))
        inner = _AMessages(*script)
        return llm._Messages(inner, meter, None), meter, inner

    def final(self, msgs):
        async def go():
            async with msgs.stream(model="claude-haiku-4-5") as s:
                return await s.get_final_message()
        return asyncio.run(go())

    def test_overload_rate_limit_and_network_are_retried_not_results(self):
        msgs, meter, inner = self.client(_api_err(anthropic.RateLimitError, 429, {"retry-after": "7"}),
                                         _api_err(anthropic.InternalServerError, 529),
                                         anthropic.APIConnectionError(request=httpx.Request("POST", "https://x")), _Msg())
        self.assertEqual(self.final(msgs).model, "claude-haiku-4-5")
        self.assertEqual(meter.infra.retries, {"http_429": 1, "http_529": 1, "network": 1})
        self.assertEqual((meter.calls, inner.n), (1, 4))

    def test_bad_request_is_not_retried(self):
        msgs, meter, inner = self.client(_api_err(anthropic.BadRequestError, 400))
        with self.assertRaises(anthropic.BadRequestError):
            self.final(msgs)
        self.assertEqual(inner.n, 1)

    def test_spend_cap_stops_the_run_and_no_request_follows(self):
        msgs, meter, inner = self.client(_Msg(inp=3_000_000), _Msg(), cap=2.0)
        with self.assertRaises(infra.SpendCapExceeded):
            self.final(msgs)
        with self.assertRaises(infra.SpendCapExceeded):
            self.final(msgs)
        self.assertEqual(inner.n, 1)

    def test_reported_model_must_equal_pin(self):
        msgs, _, _ = self.client(_Msg(model="claude-haiku-4-6"))
        with self.assertRaises(infra.InfraAbort):
            self.final(msgs)

    def test_retries_run_out_into_an_abort(self):
        msgs, _, _ = self.client(*[_api_err(anthropic.InternalServerError, 500)] * 3, attempts=3)
        with self.assertRaises(infra.InfraAbort):
            self.final(msgs)


class ThoughtSignatures(unittest.TestCase):
    def test_model_turn_is_sent_back_verbatim(self):
        """The stock element would rebuild this turn without its signature."""
        from agentdojo.agent_pipeline.llms import google_llm as gl
        sig = b"\x01signature"
        resp = T.GenerateContentResponse(candidates=[T.Candidate(content=T.Content(role="model", parts=[
            T.Part(function_call=T.FunctionCall(name="get_balance", args={}), thought_signature=sig)]))])
        sent = []

        class Client:
            class models:
                @staticmethod
                def generate_content(model, contents, config):
                    sent.append(contents)
                    return resp

        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.types import text_content_block_from_string as txt
        llm = gemini.SignatureKeepingGoogleLLM("gemini-3.8-flash", Client())
        msgs = [{"role": "system", "content": [txt("sys")]}, {"role": "user", "content": [txt("hi")]}]
        _, _, _, msgs, _ = llm.query("hi", FunctionsRuntime([]), messages=msgs)
        self.assertEqual(msgs[-1]["tool_calls"][0].function, "get_balance")
        json.dumps(msgs[-1][gemini.PARTS_KEY])  # serialisable for AgentDojo's trace logs
        llm.query("hi", FunctionsRuntime([]), messages=msgs)
        model_turn = [c for c in sent[1] if c.role == "model"][0]
        self.assertEqual(model_turn.parts[0].thought_signature, sig)
        self.assertIs(gl._message_to_google.__name__, "_message_to_google")  # patch undone


if __name__ == "__main__":
    unittest.main()
