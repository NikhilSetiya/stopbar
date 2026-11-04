"""Secondary-analysis split (PILOT §4), computed mechanically before any run:
a user task is R ("reads injectable content") if any of its AgentDojo
ground-truth calls is to a tool the frozen trust map marks untrusted-output.
No model is involved and no person reads the tasks: only task IDs and tool
names are recorded."""
from agentdojo.task_suite.load_suites import get_suite

from .pins import BENCHMARK_VERSION, SUITE, trust_map


def compute_split() -> dict:
    suite = get_suite(BENCHMARK_VERSION, SUITE)
    untrusted = set(trust_map()["untrusted_output_tools"])
    env = suite.load_and_inject_default_environment({})
    rows = {}
    for task_id, task in sorted(suite.user_tasks.items()):
        tools = [c.function for c in task.ground_truth(env.model_copy(deep=True))]
        rows[task_id] = {"ground_truth_tools": tools, "group": "R" if untrusted & set(tools) else "N"}
    return {"rule": "R if any ground-truth call is to an untrusted_output_tools entry (frozen trust map)",
            "untrusted_output_tools": sorted(untrusted), "tasks": rows,
            "counts": {g: sum(1 for r in rows.values() if r["group"] == g) for g in ("R", "N")}}
