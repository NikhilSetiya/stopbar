"""Arm A2's only difference from A0: every tool call is checked by stopbard
before it runs (LLD §18.1). Only HTTP 200 (allow) executes. Anything else
(202 escalate, 403 deny, 4xx/5xx, or no answer at all) blocks: the agent
gets a tool error with Stopbar's reason codes. Taint is not computed here;
stopbard derives it from the frozen trust map (PILOT Amendment 1.3). The
gate only names the session."""
import base64, datetime, json, os, threading, urllib.error, urllib.request, uuid
from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string


class CallLog:
    """One JSON line per gated tool call (LLD §18.5 subset)."""

    def __init__(self, path):
        self._f = open(path, "a", buffering=1)
        self._lock = threading.Lock()

    def write(self, row: dict):
        with self._lock:
            self._f.write(json.dumps(row, sort_keys=True) + "\n")


class SessionStart(BasePipelineElement):
    """Gives each episode its own Stopbar session (taint never leaks across)."""

    name = "stopbar-session"

    def query(self, query, runtime, env, messages=(), extra_args={}):
        return query, runtime, env, messages, {**extra_args, "stopbar_session": str(uuid.uuid4())}


def evaluate(url: str, session: str, tool: str, args: dict, timeout: float = 10.0) -> tuple[int, dict]:
    body = {
        "id": "req_" + uuid.uuid4().hex, "tenant": "test",
        "nonce": base64.urlsafe_b64encode(os.urandom(18)).decode(),
        "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ttl_seconds": 60, "actor": {"agent_id": "agentdojo-pilot", "session_id": session},
        "action": {"kind": "tool_call", "tool": tool, "args": args},
        "provenance": {"labels": ["trusted_user"]},
    }
    req = urllib.request.Request(url + "/v1/evaluate", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except ValueError:
            return e.code, {}
    except Exception as e:  # unreachable stopbard: fail closed, and flag it
        return 0, {"code": "GATE_UNREACHABLE", "message": str(e)}


class GatedToolsExecutor(ToolsExecutor):
    """ToolsExecutor that asks stopbard first, call by call, in order."""

    def __init__(self, url: str, log: CallLog, episode: dict, formatter):
        super().__init__(formatter)
        self.url, self.log, self.episode = url, log, episode

    def query(self, query, runtime, env, messages: Sequence = (), extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args
        session = extra_args.get("stopbar_session") or "missing-session"
        last = messages[-1]
        results = []
        for call in last["tool_calls"]:
            status, d = evaluate(self.url, session, call.function, dict(call.args))
            reasons = [r.get("policy_id") or r.get("code") for r in d.get("reasons", [])] or [d.get("code")]
            allowed = status == 200
            self.log.write({**self.episode, "session": session, "tool": call.function, "http": status,
                            "outcome": d.get("outcome", "reject"), "reasons": reasons,
                            "policy_bundle_hash": d.get("policy_bundle_hash"), "enforced": "allow" if allowed else "block",
                            "infra_error": status == 0 or status >= 500})
            if allowed:
                single = {**last, "tool_calls": [call]}
                _, runtime, env, out, extra_args = super().query(query, runtime, env, [*messages[:-1], single], extra_args)
                results.append(out[-1])
            else:
                results.append(ChatToolResultMessage(
                    role="tool", tool_call=call, tool_call_id=call.id,
                    content=[text_content_block_from_string("")],
                    error=f"Blocked by Stopbar policy (HTTP {status}): {', '.join(str(r) for r in reasons)}"))
        return query, runtime, env, [*messages, *results], extra_args
