"""Infrastructure handling shared by every model client (PILOT §6c-6d).

Infrastructure is never a task result. Rate limits, overloads, 5xx, timeouts
and network errors are retried here, below AgentDojo, so it never sees them.
When retries run out (or a quota or spend limit is hit), the client raises
InfraAbort: the run stops, the unfinished user task is discarded, and
--resume reruns it. After an abort, every further call raises at once
without a request, including AgentDojo's own retries of the same call.
"""
import json, random, subprocess, threading, time


class InfraAbort(RuntimeError):
    """Stop the run; not a task result. Deliberately not a subclass of any
    SDK error, so AgentDojo can't score it as a failed task."""


class SpendCapExceeded(InfraAbort):
    pass


def read_keychain(service: str) -> str:
    """A key from the macOS keychain. Never printed or logged."""
    r = subprocess.run(["security", "find-generic-password", "-s", service, "-w"], capture_output=True, text=True)
    if r.returncode or not r.stdout.strip():
        raise SystemExit(f"no keychain entry {service!r} (security exit {r.returncode})")
    return r.stdout.strip()


class Infra:
    """Retry policy, counters and the abort latch for one run."""

    def __init__(self, log_path=None, max_attempts: int = 12, max_wait: float = 300.0):
        self.max_attempts, self.max_wait = max_attempts, max_wait
        self.retries: dict[str, int] = {}
        self.aborted: InfraAbort | None = None
        self._lock = threading.Lock()
        self._log = open(log_path, "a", buffering=1) if log_path else None

    def note(self, **row):
        if self._log:
            with self._lock:
                self._log.write(json.dumps({"t": time.time(), **row}, sort_keys=True) + "\n")

    def check_open(self):
        if self.aborted:
            raise self.aborted

    def abort(self, exc: InfraAbort):
        self.aborted = exc
        self.note(event="abort", reason=str(exc))
        raise exc

    def backoff(self, kind: str, attempt: int, hint: float | None = None, **detail) -> float:
        """Count one retry and return how long to wait before the next try,
        or abort when attempts run out."""
        with self._lock:
            self.retries[kind] = self.retries.get(kind, 0) + 1
        if attempt >= self.max_attempts:
            self.abort(InfraAbort(f"no successful response after {attempt} attempts (last: {kind})"))
        wait = min(self.max_wait, max(hint or 0, 2 ** attempt)) + random.uniform(0, 1)
        self.note(event="retry", kind=kind, attempt=attempt, wait_s=round(wait, 1), **detail)
        return wait
