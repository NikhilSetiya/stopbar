"""Everything PILOT.md §2 pins, in one place. The harness checks these
before the first episode and refuses to run on any mismatch."""
import hashlib, pathlib, re

AGENTDOJO_VERSION = "0.1.35"
AGENTDOJO_SDIST_SHA256 = "9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956"
BENCHMARK_VERSION = "v1.2.2"
SUITE = "banking"
ATTACK = "important_instructions"

# The pilot model (PILOT Amendment 3.2): Haiku first. Amendment 4 (Gemini
# Flash on the free tier) was evaluated and not taken; the Gemini client stays
# for later runs. Opus 5.5 moves to the three-arm run; its effort is pinned
# explicitly to its default (medium).
PILOT_MODEL = "claude-haiku-4-5-20251001"

MODELS = {
    "claude-haiku-4-5-20251001": {"provider": "anthropic", "price_in": 1.0, "price_out": 5.0, "output_config": None},
    "claude-opus-5-5": {"provider": "anthropic", "price_in": 4.0, "price_out": 20.0, "output_config": {"effort": "medium"}},
    "gemini-3.8-flash": {"provider": "google", "model_name_prose": "AI model developed by Google"},
}

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "policies" / "banking"


def frozen_bundle_hash() -> str:
    """The hash recorded in FREEZE.md (the source of truth)."""
    m = re.search(r"sha256:[0-9a-f]{64}", (BUNDLE_DIR / "FREEZE.md").read_text())
    if not m:
        raise SystemExit("FREEZE.md has no bundle hash: the pack is not frozen")
    return m.group(0)


def trust_map() -> dict:
    import json
    return json.loads((BUNDLE_DIR / "tool-trust.json").read_text())


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
