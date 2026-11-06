"""Metered Together client and the run's spend/abort latch (PILOT-2 §7, §8).

Together is OpenAI-compatible, so both the victim and (via PyRIT) the attacker
are reached through the OpenAI SDK pointed at Together's base URL. Every call
goes through Meter, which:
  - records prompt and completion tokens and the dollar cost at the pinned
    per-model prices;
  - aborts the run before any further call once the stage's spend cap is
    crossed (the cap is checked after each response, so at most the call in
    flight can overshoot);
  - checks the model the API reports equals the pin, and aborts on a mismatch
    (the attacker model is an alias, so this is its only swap guard, PILOT-2 §2).

Infrastructure (rate limits, 5xx, timeouts) is retried here and never seen as
a task result. An abort is a latch: once set, every later call raises at once
without a request, so a retry loop above can't spend past the cap.
"""
import json, random, threading, time

# Together list prices, $ per 1M tokens (input, output), fetched 2026-11-05;
# re-checked at freeze. Keyed by the exact pinned model id.
PRICES = {
    "deepseek-ai/DeepSeek-V4.1-Flash-1017": (0.30, 1.20),
    "Qwen/Qwen3.5-9B": (0.17, 0.25),
}
BASE_URL = "https://api.together.xyz/v1"
KEYCHAIN_SERVICE = "stopbar-together-key"


class Abort(RuntimeError):
    """Stop the run; never a task result."""


class SpendCapExceeded(Abort):
    pass


class ModelMismatch(Abort):
    pass


class Meter:
    """Spend, token counts and the abort latch for one run, shared by every
    model call (victim and attacker)."""

    def __init__(self, cap_usd: float, log_path=None, max_attempts: int = 10, max_wait: float = 120.0):
        self.cap_usd = cap_usd
        self.max_attempts, self.max_wait = max_attempts, max_wait
        self.input_tokens: dict[str, int] = {}
        self.output_tokens: dict[str, int] = {}
        self.calls: dict[str, int] = {}
        self.reported: dict[str, set] = {}
        self.retries: dict[str, int] = {}
        self.aborted: Abort | None = None
        self._lock = threading.Lock()
        self._log = open(log_path, "a", buffering=1) if log_path else None

    @property
    def usd(self) -> float:
        total = 0.0
        for m, (pin, pout) in PRICES.items():
            total += self.input_tokens.get(m, 0) * pin / 1e6 + self.output_tokens.get(m, 0) * pout / 1e6
        return total

    def note(self, **row):
        if self._log:
            with self._lock:
                self._log.write(json.dumps({"t": time.time(), **row}, sort_keys=True) + "\n")

    def check_open(self):
        if self.aborted:
            raise self.aborted

    def abort(self, exc: Abort):
        self.aborted = exc
        self.note(event="abort", reason=str(exc))
        raise exc

    def record(self, model: str, reported_model: str, usage) -> None:
        with self._lock:
            self.calls[model] = self.calls.get(model, 0) + 1
            self.input_tokens[model] = self.input_tokens.get(model, 0) + (getattr(usage, "prompt_tokens", 0) or 0)
            self.output_tokens[model] = self.output_tokens.get(model, 0) + (getattr(usage, "completion_tokens", 0) or 0)
            self.reported.setdefault(model, set()).add(reported_model)
            over = self.usd > self.cap_usd
        if reported_model != model:
            self.abort(ModelMismatch(f"requested {model!r}, API reported {reported_model!r}: stopping"))
        if over:
            self.abort(SpendCapExceeded(f"spend ${self.usd:.4f} exceeded the cap ${self.cap_usd:.2f}"))

    def backoff(self, kind: str, attempt: int, hint: float | None = None, **detail) -> float:
        with self._lock:
            self.retries[kind] = self.retries.get(kind, 0) + 1
        if attempt >= self.max_attempts:
            self.abort(Abort(f"no successful response after {attempt} attempts (last: {kind})"))
        wait = min(self.max_wait, max(hint or 0, 2 ** attempt)) + random.uniform(0, 1)
        self.note(event="retry", kind=kind, attempt=attempt, wait_s=round(wait, 1), **detail)
        return wait

    def summary(self) -> dict:
        return {"spend_usd": round(self.usd, 4), "calls": dict(self.calls),
                "input_tokens": dict(self.input_tokens), "output_tokens": dict(self.output_tokens),
                "reported_models": {m: sorted(v) for m, v in self.reported.items()},
                "retries": dict(self.retries), "aborted": str(self.aborted) if self.aborted else None}


# Retriable transient failures from the OpenAI SDK (status codes).
RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class MeteredChat:
    """Wraps one OpenAI-compatible client for one pinned model. create() takes
    the same args as client.chat.completions.create minus `model`."""

    def __init__(self, client, model: str, meter: Meter):
        if model not in PRICES:
            raise SystemExit(f"model {model!r} is not priced in PILOT-2 §8")
        self.client, self.model, self.meter = client, model, meter

    def create(self, **kw):
        import openai

        self.meter.check_open()
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.client.chat.completions.create(model=self.model, **kw)
            except openai.APIStatusError as e:
                if getattr(e, "status_code", None) not in RETRY_STATUS:
                    raise
                hint = _retry_after(e)
                time.sleep(self.meter.backoff(f"http_{e.status_code}", attempt, hint))
            except (openai.APIConnectionError, openai.APITimeoutError) as e:
                time.sleep(self.meter.backoff("network", attempt, error=type(e).__name__))
            else:
                self.meter.record(self.model, resp.model, resp.usage)
                return resp


def _retry_after(e) -> float | None:
    try:
        return float(e.response.headers.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None


def make_client(meter: Meter, model: str) -> MeteredChat:
    import openai

    from .infra import read_keychain
    client = openai.OpenAI(base_url=BASE_URL, api_key=read_keychain(KEYCHAIN_SERVICE), max_retries=0, timeout=120.0)
    return MeteredChat(client, model, meter)
