"""Run one (model, arm) of the pilot (PILOT.md). Usage:

  python -m harness.run --arm A0|A2 --model claude-haiku-4-5 --out results/ [--stopbard URL] [--cap-usd 20]
  python -m harness.run --arm A2 --dry-run --stopbard URL --out results/   # no API: scripted ground-truth agent

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
from .pins import (AGENTDOJO_SDIST_SHA256, AGENTDOJO_VERSION, ATTACK, BENCHMARK_VERSION, BUNDLE_DIR, SUITE,
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=["A0", "A2"], required=True)
    ap.add_argument("--model")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--stopbard", default="http://127.0.0.1:7777")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--cap-usd", type=float, default=20.0)
    ap.add_argument("--limit", type=int, default=0, help="first N user tasks only (smoke runs; never for results)")
    a = ap.parse_args()
    if not a.dry_run and not a.model:
        ap.error("--model is required unless --dry-run")

    # ---- pins: refuse to start on any mismatch ----
    if importlib.metadata.version("agentdojo") != AGENTDOJO_VERSION:
        raise SystemExit(f"agentdojo {importlib.metadata.version('agentdojo')} != pinned {AGENTDOJO_VERSION}")
    frozen = frozen_bundle_hash()
    bundle = None
    if a.arm == "A2":
        bundle = probe_bundle_hash(a.stopbard)
        if bundle != frozen:
            raise SystemExit(f"stopbard enforces {bundle}, frozen bundle is {frozen}: refusing to run")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=BUNDLE_DIR).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "."], capture_output=True, text=True, cwd=BUNDLE_DIR).stdout.strip()
    if dirty:
        raise SystemExit("the policy bundle directory has uncommitted changes: refusing to run")

    started = datetime.datetime.now(datetime.timezone.utc)
    tag = "dry-run" if a.dry_run else a.model
    out = a.out / f"{started:%Y%m%dT%H%M%SZ}_{tag}_{a.arm}"
    out.mkdir(parents=True)
    suite = get_suite(BENCHMARK_VERSION, SUITE)
    split = compute_split()
    (out / "split.json").write_text(json.dumps(split, indent=2, sort_keys=True))

    meter, adaptations = None, {}
    if a.dry_run:
        from agentdojo import models as ad_models
        ad_models.MODEL_NAMES.setdefault(ScriptedAgent.name, "Claude")
    else:
        from .llm import make_llm
        llm, meter, adaptations = make_llm(a.model, a.cap_usd)
    run = {"arm": a.arm, "dry_run": a.dry_run, "model_id_requested": a.model, "started_utc": started.isoformat(),
           "agentdojo_version": AGENTDOJO_VERSION, "agentdojo_sdist_sha256": AGENTDOJO_SDIST_SHA256,
           "benchmark_version": BENCHMARK_VERSION, "suite": SUITE, "attack": ATTACK,
           "stopbar_commit": commit, "frozen_bundle_hash": frozen, "enforced_bundle_hash": bundle,
           "model_adaptations": adaptations, "cap_usd": a.cap_usd, "limit": a.limit}
    (out / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))

    log = gate.CallLog(out / "calls.jsonl") if a.arm == "A2" else None
    episodes = open(out / "episodes.jsonl", "w", buffering=1)
    task_ids = sorted(suite.user_tasks)[: a.limit or None]
    logdir = out / "agentdojo_logs"  # AgentDojo's own per-episode traces
    try:
        with OutputLogger(str(logdir)):
            for uid in task_ids:
                task = suite.user_tasks[uid]
                llm_for_task = ScriptedAgent(task) if a.dry_run else llm
                # benign
                p = pipeline(llm_for_task, a.arm, a.stopbard, log, {"user_task": uid, "injection_task": None})
                utility, _ = run_task_without_injection_tasks(suite, p, task, logdir=logdir, force_rerun=True, benchmark_version=BENCHMARK_VERSION)
                episodes.write(json.dumps({"user_task": uid, "injection_task": None, "utility": bool(utility)}) + "\n")
                # under attack: AgentDojo's own attack and security check, unmodified
                p = pipeline(llm_for_task, a.arm, a.stopbard, log, {"user_task": uid, "injection_task": "*"})
                attack = load_attack(ATTACK, suite, p)
                utils, secs = run_task_with_injection_tasks(suite, p, task, attack, logdir=logdir, force_rerun=True, benchmark_version=BENCHMARK_VERSION)
                for (u, inj), ok in utils.items():
                    episodes.write(json.dumps({"user_task": u, "injection_task": inj, "utility": bool(ok), "attack_success": bool(secs[(u, inj)])}) + "\n")
    finally:
        run["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if meter:
            run.update({"model_ids_reported": sorted(meter.reported_models), "api_calls": meter.calls,
                        "input_tokens": meter.input_tokens, "output_tokens": meter.output_tokens, "spend_usd": round(meter.usd, 4)})
        (out / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))
    print(out)


if __name__ == "__main__":
    sys.exit(main())
