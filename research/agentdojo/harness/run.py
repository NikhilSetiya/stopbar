"""Run the pilot (PILOT.md), both arms interleaved per user task. Usage:

  python -m harness.run --model claude-haiku-4-5-20251001 --cap-usd 20 --out results/ [--stopbard URL]
  python -m harness.run --resume results/<run dir> [--stopbard URL]        # after a quota stop
  python -m harness.run --dry-run --stopbard URL --out results/            # no API: scripted ground-truth agent

For each user task it runs A0 then A2 on the benign episode, then A0 then A2
on every injection pair (Amendment 4), so the arms see the same API
conditions. A user task counts only once both arms finish it; if the run
stops part-way (quota, infrastructure), that task's partial episodes are
discarded and --resume reruns it. Infrastructure trouble is never a task result.

Before the first episode it writes run.json (exact model ID, UTC date/time,
AgentDojo version + sha256, benchmark version, Stopbar commit, bundle hash)
and refuses to start on any mismatch with the pins or the frozen bundle.
"""
import argparse, datetime, importlib.metadata, json, pathlib, subprocess, sys, uuid
from functools import partial

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor, tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

from . import gate
from .infra import Infra
from .pins import (AGENTDOJO_SDIST_SHA256, AGENTDOJO_VERSION, ATTACK, BENCHMARK_VERSION, BUNDLE_DIR, MODELS, SUITE,
                   frozen_bundle_hash)
from .split import compute_split


class ScriptedAgent(BasePipelineElement):
    """Dry-run stand-in for the LLM: replays the task's ground-truth calls,
    one per turn, through the real tools loop (so A2's gate sees each), then
    answers. No API calls, no cost: it exercises the harness, not a model."""

    name = "claude-dry-run-scripted"

    def __init__(self, task):
        self.task = task

    def query(self, query, runtime, env, messages=(), extra_args={}):
        done = sum(1 for m in messages if m["role"] == "tool")
        calls = extra_args.get("_script")
        if calls is None:
            calls = self.task.ground_truth(env.model_copy(deep=True))
            extra_args = {**extra_args, "_script": calls}
        if done < len(calls):
            msg = ChatAssistantMessage(role="assistant", tool_calls=[calls[done]], content=[text_content_block_from_string("")])
        else:
            msg = ChatAssistantMessage(role="assistant", tool_calls=None, content=[text_content_block_from_string(self.task.GROUND_TRUTH_OUTPUT)])
        return query, runtime, env, [*messages, msg], extra_args


def pipeline(llm, arm: str, url: str | None, log: gate.CallLog | None, episode: dict):
    """AgentDojo's stock pipeline (as AgentPipeline.from_config builds it for
    defense=None). A2 differs only by the gated executor and a session id."""
    fmt = tool_result_to_str
    executor = gate.GatedToolsExecutor(url, log, episode, fmt) if arm == "A2" else ToolsExecutor(fmt)
    elems = [SystemMessage(load_system_message(None)), InitQuery()]
    if arm == "A2":
        elems.insert(0, gate.SessionStart())
    p = AgentPipeline([*elems, llm, ToolsExecutionLoop([executor, llm])])
    p.name = llm.name if hasattr(llm, "name") and llm.name else "claude"
    return p


def probe_bundle_hash(url: str) -> str:
    """Ask the running stopbard which bundle it enforces (a declared read in a
    throwaway session; it reports policy_bundle_hash on every decision)."""
    status, d = gate.evaluate(url, "probe-" + uuid.uuid4().hex, "get_balance", {})
    if status != 200 or not d.get("policy_bundle_hash"):
        raise SystemExit(f"stopbard probe failed: HTTP {status} {d}")
    return d["policy_bundle_hash"]


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def keep_done(path: pathlib.Path, done: set[str]):
    """Drop rows of unfinished user tasks (a stopped run's partial task)."""
    if path.exists():
        rows = [l for l in path.read_text().splitlines() if l and json.loads(l)["user_task"] in done]
        path.write_text("".join(r + "\n" for r in rows))


def done_tasks(out: pathlib.Path) -> set[str]:
    p = out / "progress.jsonl"
    return {json.loads(l)["user_task"] for l in p.read_text().splitlines() if l} if p.exists() else set()


ARMS = ("A0", "A2")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--resume", type=pathlib.Path, help="continue a stopped run in this directory")
    ap.add_argument("--stopbard", default="http://127.0.0.1:7777")
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--cap-usd", type=float, default=20.0, help="hard spend cap across the whole run, all segments (Anthropic)")
    ap.add_argument("--limit", type=int, default=0, help="first N user tasks only (smoke runs; never for results)")
    a = ap.parse_args()

    prev = None
    if a.resume:
        prev = json.loads((a.resume / "run.json").read_text())
        a.model, a.dry_run, a.limit = prev["model_id_requested"], prev["dry_run"], prev["limit"]
    elif not a.out or (not a.dry_run and not a.model):
        ap.error("--out and (--model or --dry-run) are required unless --resume")
    if a.model and a.model not in MODELS:
        ap.error(f"model {a.model} is not pinned")

    # ---- pins: refuse to start on any mismatch ----
    if importlib.metadata.version("agentdojo") != AGENTDOJO_VERSION:
        raise SystemExit(f"agentdojo {importlib.metadata.version('agentdojo')} != pinned {AGENTDOJO_VERSION}")
    frozen = frozen_bundle_hash()
    bundle = probe_bundle_hash(a.stopbard)
    if bundle != frozen:
        raise SystemExit(f"stopbard enforces {bundle}, frozen bundle is {frozen}: refusing to run")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=BUNDLE_DIR).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "."], capture_output=True, text=True, cwd=BUNDLE_DIR).stdout.strip()
    if dirty:
        raise SystemExit("the policy bundle directory has uncommitted changes: refusing to run")

    suite = get_suite(BENCHMARK_VERSION, SUITE)
    if prev:
        out = a.resume
        for k, v in (("stopbar_commit", commit), ("frozen_bundle_hash", frozen), ("agentdojo_version", AGENTDOJO_VERSION)):
            if prev[k] != v:
                raise SystemExit(f"resume: {k} is {v}, the run started with {prev[k]}: refusing to mix")
        run = prev
    else:
        started = datetime.datetime.now(datetime.timezone.utc)
        out = a.out / f"{started:%Y%m%dT%H%M%SZ}_{'dry-run' if a.dry_run else a.model}"
        for arm in ARMS:
            (out / arm).mkdir(parents=True)
        (out / "split.json").write_text(json.dumps(compute_split(), indent=2, sort_keys=True))
        run = {"arms": list(ARMS), "interleaved": "per user task: benign A0, A2; then attacked A0, A2",
               "dry_run": a.dry_run, "model_id_requested": a.model, "started_utc": started.isoformat(),
               "agentdojo_version": AGENTDOJO_VERSION, "agentdojo_sdist_sha256": AGENTDOJO_SDIST_SHA256,
               "benchmark_version": BENCHMARK_VERSION, "suite": SUITE, "attack": ATTACK,
               "stopbar_commit": commit, "frozen_bundle_hash": frozen, "limit": a.limit, "segments": []}
    done = done_tasks(out)
    for arm in ARMS:
        keep_done(out / arm / "episodes.jsonl", done)
    keep_done(out / "A2" / "calls.jsonl", done)

    meter = guard = None
    infra = Infra(out / "infra.jsonl")
    provider = MODELS[a.model]["provider"] if a.model else None
    if a.dry_run:
        from agentdojo import models as ad_models
        ad_models.MODEL_NAMES.setdefault(ScriptedAgent.name, "Claude")
        adaptations = {}
    elif provider == "google":
        from . import gemini
        llm, guard, adaptations = gemini.make_llm(a.model, MODELS[a.model], infra)
        run["model_version_listed"] = llm.client.inner.models.get(model=a.model).version
    else:
        from .llm import make_llm
        cap = prev.get("cap_usd", a.cap_usd) if prev else a.cap_usd  # the cap covers every segment
        spent = sum(s.get("spend_usd") or 0 for s in run["segments"])
        llm, meter, adaptations = make_llm(a.model, cap - spent, infra)
        run["cap_usd"] = cap
    if not a.dry_run:
        adaptations["infrastructure"] = ("rate limits, overloads, 5xx, timeouts and network errors retried with backoff in the "
                                         "client (SDK retries off); exhausted retries, a quota or the spend cap stop the run, "
                                         "and the unfinished user task is rerun on --resume")
    run["model_adaptations"] = adaptations
    seg = {"started_utc": now(), "enforced_bundle_hash": bundle, "tasks_already_done": len(done)}
    run["segments"].append(seg)
    (out / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))

    log = gate.CallLog(out / "A2" / "calls.jsonl")
    episodes = {arm: open(out / arm / "episodes.jsonl", "a", buffering=1) for arm in ARMS}
    progress = open(out / "progress.jsonl", "a", buffering=1)
    task_ids = [t for t in sorted(suite.user_tasks)[: a.limit or None] if t not in done]
    stopped = None
    try:
        with OutputLogger(str(out / "agentdojo_logs")):
            for uid in task_ids:
                task = suite.user_tasks[uid]
                agent = ScriptedAgent(task) if a.dry_run else llm
                for arm in ARMS:  # benign
                    p = pipeline(agent, arm, a.stopbard, log, {"user_task": uid, "injection_task": None})
                    utility, _ = run_task_without_injection_tasks(suite, p, task, logdir=out / "agentdojo_logs" / arm,
                                                                  force_rerun=True, benchmark_version=BENCHMARK_VERSION)
                    episodes[arm].write(json.dumps({"user_task": uid, "injection_task": None, "utility": bool(utility)}) + "\n")
                for arm in ARMS:  # under attack: AgentDojo's own attack and security check, unmodified
                    p = pipeline(agent, arm, a.stopbard, log, {"user_task": uid, "injection_task": "*"})
                    utils, secs = run_task_with_injection_tasks(suite, p, task, load_attack(ATTACK, suite, p),
                                                                logdir=out / "agentdojo_logs" / arm, force_rerun=True,
                                                                benchmark_version=BENCHMARK_VERSION)
                    for (u, inj), ok in utils.items():
                        episodes[arm].write(json.dumps({"user_task": u, "injection_task": inj, "utility": bool(ok),
                                                        "attack_success": bool(secs[(u, inj)])}) + "\n")
                progress.write(json.dumps({"user_task": uid, "finished_utc": now()}) + "\n")
    except Exception:
        # AgentDojo may wrap our abort (its Anthropic retry raises tenacity's
        # RetryError), so the latch, not the exception type, says it was ours.
        if not infra.aborted:
            raise
        stopped = infra.aborted  # infrastructure, not a result: the unfinished task is dropped on resume
    finally:
        seg["finished_utc"] = now()
        seg["tasks_done_total"] = len(done_tasks(out))
        if stopped:
            seg["stopped"] = f"{type(stopped).__name__}: {stopped}"
        if meter:
            seg.update({"model_ids_reported": sorted(meter.reported_models), "api_calls": meter.calls,
                        "input_tokens": meter.input_tokens, "output_tokens": meter.output_tokens, "spend_usd": round(meter.usd, 4)})
        if guard:
            seg.update({"model_versions_reported": sorted(guard.reported_models), "service_tiers_seen": sorted(guard.tiers),
                        "api_calls": guard.calls, "prompt_tokens": guard.prompt_tokens, "output_tokens": guard.output_tokens,
                        "thought_tokens": guard.thought_tokens})
        seg["infra_retries"] = dict(infra.retries)
        (out / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))
    print(out)
    if stopped:
        print(f"stopped: {stopped}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
