"""Model clients for the pilot (PILOT §2, Amendment 1).

Adaptations to AgentDojo's stock Anthropic element, each recorded in run.json:
- the pinned model IDs are registered in AgentDojo's MODEL_NAMES with the
  same prose name AgentDojo uses for every Claude model ("Claude"), so the
  unmodified important_instructions attack can address the agent exactly as
  it would any other Claude model;
- claude-opus-5-5: no temperature (rejected by the API), effort pinned to
  "medium" via output_config, and max_tokens raised from AgentDojo's 1024
  because adaptive thinking (which can't be disabled) counts against it;
- every response is metered against a hard spend cap, and the model ID the
  API reports is recorded.
"""
import threading

from agentdojo import models as ad_models
from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM

from .pins import MODELS


class SpendCapExceeded(RuntimeError):
    pass


class Meter:
    def __init__(self, model: str, cap_usd: float):
        self.model, self.cap = model, cap_usd
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
            if self.usd > self.cap:
                raise SpendCapExceeded(f"spend ${self.usd:.2f} exceeded the cap ${self.cap:.2f}")


class _Stream:
    def __init__(self, cm, meter):
        self.cm, self.meter = cm, meter

    async def __aenter__(self):
        self.stream = await self.cm.__aenter__()
        return self

    async def __aexit__(self, *a):
        return await self.cm.__aexit__(*a)

    async def get_final_message(self):
        msg = await self.stream.get_final_message()
        self.meter.record(msg)
        return msg


class _Messages:
    def __init__(self, inner, meter, output_config):
        self.inner, self.meter, self.output_config = inner, meter, output_config

    def stream(self, **kw):
        if self.output_config:
            kw["extra_body"] = {**kw.get("extra_body", {}), "output_config": self.output_config}
        return _Stream(self.inner.stream(**kw), self.meter)


class MeteredClient:
    """Wraps AsyncAnthropic: injects pinned output_config and meters spend."""

    def __init__(self, inner, meter, output_config):
        self.messages = _Messages(inner.messages, meter, output_config)


def make_llm(model: str, cap_usd: float):
    import anthropic

    if model not in MODELS:
        raise SystemExit(f"model {model} is not pinned in PILOT §2")
    ad_models.MODEL_NAMES.setdefault(model, "Claude")  # same prose name as every Claude model
    meter = Meter(model, cap_usd)
    client = MeteredClient(anthropic.AsyncAnthropic(), meter, MODELS[model]["output_config"])
    if model == "claude-opus-5-5":
        llm = AnthropicLLM(client, model, temperature=None, max_tokens=16000)
    else:
        llm = AnthropicLLM(client, model)  # AgentDojo's stock settings
    adaptations = {
        "model_names_entry": {model: "Claude"},
        "temperature": None if model == "claude-opus-5-5" else 0.0,
        "max_tokens": 16000 if model == "claude-opus-5-5" else 1024,
        "output_config": MODELS[model]["output_config"],
    }
    return llm, meter, adaptations
