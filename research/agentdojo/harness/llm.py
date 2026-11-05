"""Anthropic model client (PILOT §2, Amendments 1 and 3).

Adaptations to AgentDojo's stock Anthropic element, each recorded in run.json:
- the pinned model IDs are registered in AgentDojo's MODEL_NAMES with the
  same prose name AgentDojo uses for every Claude model ("Claude"), so the
  unmodified important_instructions attack addresses the agent exactly as
  it would any other Claude model;
- claude-opus-5-5: no temperature (rejected by the API), effort pinned to
  "medium" via output_config, and max_tokens raised from AgentDojo's 1024
  because adaptive thinking (which can't be disabled) counts against it;
- the API key is read from the macOS keychain and never logged.

Every response is metered against a hard spend cap, and the model ID the API
reports is recorded. Infrastructure (harness.infra): rate limits, overloads,
5xx, timeouts and network errors are retried here with backoff (honouring
retry-after); the SDK's own retries are off so every retry is counted.
"""
import asyncio, threading

import anthropic
from agentdojo import models as ad_models
from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM

from .infra import Infra, InfraAbort, SpendCapExceeded, read_keychain
from .pins import MODELS

KEYCHAIN_SERVICE = "stopbar-anthropic-key"
RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class Meter:
    def __init__(self, model: str, cap_usd: float, infra: Infra):
        self.model, self.cap, self.infra = model, cap_usd, infra
        self.input_tokens = self.output_tokens = self.calls = 0
        self.reported_models: set[str] = set()
        self._lock = threading.Lock()

    @property
    def usd(self) -> float:
        p = MODELS[self.model]
        return (self.input_tokens * p["price_in"] + self.output_tokens * p["price_out"]) / 1e6

    def record(self, message):
        with self._lock:
            u = message.usage
            self.input_tokens += (u.input_tokens or 0) + (getattr(u, "cache_read_input_tokens", 0) or 0) + (getattr(u, "cache_creation_input_tokens", 0) or 0)
            self.output_tokens += u.output_tokens or 0
            self.calls += 1
            self.reported_models.add(message.model)
            over = self.usd > self.cap
        if over:
            self.infra.abort(SpendCapExceeded(f"spend ${self.usd:.2f} exceeded the cap ${self.cap:.2f}"))
        if message.model != self.model:
            self.infra.abort(InfraAbort(f"API reports model {message.model!r}, pinned {self.model!r}"))


def _retry_hint(e) -> float | None:
    try:
        return float(e.response.headers.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None


class _Stream:
    """Stands in for the SDK's stream manager. The request (with retries)
    happens in get_final_message, which is all AgentDojo calls.

    Each attempt uses a fresh SDK client, closed afterwards: AgentDojo runs
    every query in its own asyncio.run(), and a pooled connection from the
    previous event loop fails ("Event loop is closed"). In the PILOT run that
    cost one network retry per call (PILOT §7.1)."""

    def __init__(self, sdk_factory, kw, meter: Meter):
        self.sdk_factory, self.kw, self.meter = sdk_factory, kw, meter

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get_final_message(self):
        infra = self.meter.infra
        infra.check_open()
        attempt = 0
        while True:
            attempt += 1
            sdk = self.sdk_factory()
            try:
                async with sdk.messages.stream(**self.kw) as s:
                    msg = await s.get_final_message()
            except anthropic.APIStatusError as e:
                if e.status_code not in RETRY_STATUS:
                    raise  # a real 4xx: AgentDojo's own handling applies
                wait = infra.backoff(f"http_{e.status_code}", attempt, _retry_hint(e), request_id=getattr(e, "request_id", None))
            except (anthropic.APIConnectionError, anthropic.APITimeoutError) as e:
                wait = infra.backoff("network", attempt, error=type(e).__name__)
            else:
                self.meter.record(msg)
                return msg
            finally:
                await sdk.close()
            await asyncio.sleep(wait)


class _Messages:
    def __init__(self, sdk_factory, meter, output_config):
        self.sdk_factory, self.meter, self.output_config = sdk_factory, meter, output_config

    def stream(self, **kw):
        if self.output_config:
            kw["extra_body"] = {**kw.get("extra_body", {}), "output_config": self.output_config}
        return _Stream(self.sdk_factory, kw, self.meter)


class MeteredClient:
    """Stands in for AsyncAnthropic: injects pinned output_config, meters
    spend, retries infrastructure. sdk_factory returns a new AsyncAnthropic."""

    def __init__(self, sdk_factory, meter, output_config):
        self.messages = _Messages(sdk_factory, meter, output_config)


def make_llm(model: str, cap_usd: float, infra: Infra):
    if model not in MODELS:
        raise SystemExit(f"model {model} is not pinned in PILOT §2")
    ad_models.MODEL_NAMES.setdefault(model, "Claude")  # same prose name as every Claude model
    meter = Meter(model, cap_usd, infra)
    key = read_keychain(KEYCHAIN_SERVICE)
    client = MeteredClient(lambda: anthropic.AsyncAnthropic(api_key=key, max_retries=0, timeout=300.0),
                           meter, MODELS[model]["output_config"])
    if model == "claude-opus-5-5":
        llm = AnthropicLLM(client, model, temperature=None, max_tokens=16000)
    else:
        llm = AnthropicLLM(client, model)  # AgentDojo's stock settings
    llm.name = model
    adaptations = {
        "model_names_entry": {model: "Claude"},
        "temperature": None if model == "claude-opus-5-5" else 0.0,
        "max_tokens": 16000 if model == "claude-opus-5-5" else 1024,
        "output_config": MODELS[model]["output_config"],
        "api_key": f"macOS keychain service {KEYCHAIN_SERVICE!r}; never logged",
    }
    return llm, meter, adaptations
