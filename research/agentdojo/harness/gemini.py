"""Gemini client (PILOT Amendment 4: evaluated for the pilot and not taken;
kept for later runs).

Client adaptations to AgentDojo's stock GoogleLLM, recorded in run.json;
none touches the attack text, the tools or the scoring:
- the pinned model ID gets AgentDojo's own MODEL_NAMES prose for Gemini
  ("AI model developed by Google");
- thought signatures are kept: Gemini 3 rejects a function-call turn sent
  back without its thought_signature (HTTP 400), and the stock element
  rebuilds model turns from text and tool calls only. We store the model's
  parts verbatim on the assistant message and send them back unchanged;
- the API key is read from the macOS keychain and never logged.

Infrastructure (harness.infra): 429 per-minute quota, 5xx, timeouts and
network errors are retried here. (AgentDojo's benchmark loop scores a Gemini
ServerError as a failed task, so they must never reach it.) A per-day quota
stops the run (resumable). A 429 naming a quota that isn't a FreeTier quota
stops it too. That is the only billing evidence the API gives: on a
free-tier key the x-gemini-service-tier header says "standard", so the
header describes the service level, not billing. It is recorded, not
enforced.
"""
import threading, time

import httpx

from agentdojo import models as ad_models
from agentdojo.agent_pipeline.llms import google_llm as gl
from google import genai
from google.genai import types as T
from google.genai.errors import ClientError, ServerError

from .infra import Infra, InfraAbort, read_keychain

KEYCHAIN_SERVICE = "stopbar-gemini-key"
TIER_HEADER = "x-gemini-service-tier"
PARTS_KEY = "_gemini_parts"  # verbatim model parts on an assistant message


class BilledTier(InfraAbort):
    pass


def quota_info(err: ClientError) -> tuple[list[str], float | None]:
    """Quota IDs and retry delay (seconds) from a 429's error details."""
    details = ((err.details or {}).get("error") or {}).get("details") or []
    ids, delay = [], None
    for d in details:
        t = d.get("@type", "")
        if t.endswith("QuotaFailure"):
            ids += [v.get("quotaId", "") for v in d.get("violations", [])]
        elif t.endswith("RetryInfo") and str(d.get("retryDelay", "")).endswith("s"):
            delay = float(d["retryDelay"][:-1])
    return ids, delay


class Guard:
    """Counts and records Gemini responses; enforces the pin and the quota rules."""

    def __init__(self, model: str, infra: Infra):
        self.model, self.infra = model, infra
        self.calls = self.prompt_tokens = self.output_tokens = self.thought_tokens = 0
        self.reported_models: set[str] = set()
        self.tiers: set[str] = set()
        self._lock = threading.Lock()

    def check(self, resp):
        h = resp.sdk_http_response.headers if resp.sdk_http_response else None
        with self._lock:
            self.calls += 1
            u = resp.usage_metadata
            if u:
                self.prompt_tokens += u.prompt_token_count or 0
                self.output_tokens += u.candidates_token_count or 0
                self.thought_tokens += u.thoughts_token_count or 0
            if resp.model_version:
                self.reported_models.add(resp.model_version)
            self.tiers.add(str((h or {}).get(TIER_HEADER)))
        if resp.model_version != self.model:
            self.infra.abort(InfraAbort(f"API reports model {resp.model_version!r}, pinned {self.model!r}"))


class _Models:
    def __init__(self, inner, guard: Guard):
        self.inner, self.g = inner, guard

    def generate_content(self, **kw):
        infra = self.g.infra
        infra.check_open()
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.inner.generate_content(**kw)
            except ClientError as e:
                if e.code != 429:
                    raise  # a real 4xx: AgentDojo's own handling applies
                ids, delay = quota_info(e)
                if any("FreeTier" not in q for q in ids):
                    infra.abort(BilledTier(f"429 names a non-free-tier quota {ids}"))
                if any("PerDay" in q for q in ids):
                    infra.abort(InfraAbort(f"daily free-tier quota exhausted {ids}: resume later with --resume"))
                wait = infra.backoff("429", attempt, delay, quota_ids=ids)
            except (ServerError, httpx.TransportError, OSError) as e:
                wait = infra.backoff("5xx_or_network", attempt, error=type(e).__name__, code=getattr(e, "code", None))
            else:
                self.g.check(resp)
                return resp
            time.sleep(wait)


class GuardedClient:
    """Stands in for genai.Client where GoogleLLM uses it (client.models)."""

    def __init__(self, inner: genai.Client, guard: Guard):
        self.inner = inner  # keep it alive: a collected genai.Client closes its HTTP connection
        self.models = _Models(inner.models, guard)


def _parts_to_json(parts) -> list[dict]:
    return [p.model_dump(mode="json", exclude_none=True) for p in parts]


class SignatureKeepingGoogleLLM(gl.GoogleLLM):
    """GoogleLLM, except that model turns are sent back verbatim (with their
    thought signatures) instead of being rebuilt from text and tool calls."""

    def query(self, query, runtime, env=gl.EmptyEnv(), messages=(), extra_args={}):
        original = gl._message_to_google

        def to_google(m):
            if m["role"] == "assistant" and m.get(PARTS_KEY):
                return T.Content(role="model", parts=[T.Part.model_validate(p) for p in m[PARTS_KEY]])
            return original(m)

        stock_convert = gl._google_to_assistant_message

        def from_google(resp):
            msg = stock_convert(resp)
            c = resp.candidates[0].content if resp.candidates else None
            if c is not None and c.parts:
                msg[PARTS_KEY] = _parts_to_json(c.parts)
            return msg

        with _patched(gl, _message_to_google=to_google, _google_to_assistant_message=from_google):
            return super().query(query, runtime, env, messages, extra_args)


class _patched:
    """Swap module attributes for the duration of one query (GoogleLLM calls
    them as module globals). Queries in one process run one at a time."""

    _lock = threading.Lock()

    def __init__(self, mod, **attrs):
        self.mod, self.attrs = mod, attrs

    def __enter__(self):
        self._lock.acquire()
        self.saved = {k: getattr(self.mod, k) for k in self.attrs}
        for k, v in self.attrs.items():
            setattr(self.mod, k, v)

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(self.mod, k, v)
        self._lock.release()


def make_llm(model: str, spec: dict, infra: Infra):
    ad_models.MODEL_NAMES.setdefault(model, spec["model_name_prose"])
    guard = Guard(model, infra)
    # One attempt per SDK call (our loop does the retrying and counting) and a
    # per-request timeout, so a hung request becomes a counted retry.
    http = T.HttpOptions(timeout=180_000, retry_options=T.HttpRetryOptions(attempts=1))
    client = GuardedClient(genai.Client(api_key=read_keychain(KEYCHAIN_SERVICE), http_options=http), guard)
    llm = SignatureKeepingGoogleLLM(model, client)  # stock temperature 0.0, max_tokens 65535
    llm.name = model
    adaptations = {
        "model_names_entry": {model: spec["model_name_prose"]},
        "thought_signatures": "model turns sent back verbatim (stock element drops thought_signature; Gemini 3 returns HTTP 400 without it)",
        "temperature": llm.temperature, "max_tokens": llm.max_tokens,
        "api_key": f"macOS keychain service {KEYCHAIN_SERVICE!r}; never logged",
    }
    return llm, guard, adaptations
