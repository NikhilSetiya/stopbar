# AgentDojo pilot harness (CS-503)

The protocol is [`PILOT.md`](PILOT.md), the pre-registration. The frozen policy bundle is in [`policies/banking/`](policies/banking/FREEZE.md).

```bash
cd research/agentdojo
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock   # agentdojo==0.1.35 + pinned deps
.venv/bin/python -m unittest discover -s tests                        # harness unit tests

# stopbard with the frozen bundle (from the repo root, in another terminal):
#   echo '{"limits_disabled": true}' > /tmp/world.json
#   stopbard -listen 127.0.0.1:7777 -dev-world /tmp/world.json -policies research/agentdojo/policies/banking -state-dir /tmp/pilot-state

.venv/bin/python -m harness.run --arm A2 --dry-run --out results/       # free: scripted ground-truth agent, no API
.venv/bin/python -m harness.run --arm A0 --model claude-haiku-4-5 --out results/ --cap-usd 20   # PAID
.venv/bin/python -m harness.run --arm A2 --model claude-haiku-4-5 --out results/ --cap-usd 20   # PAID
.venv/bin/python -m harness.analyze results/<A0 dir> results/<A2 dir>
```

The runner refuses to start if:
- the AgentDojo version differs from the pin
- A2's `stopbard` enforces any bundle other than the frozen hash
- the bundle directory has uncommitted changes

Before the first episode it writes `run.json`: the requested model ID (the model IDs the API reports back are added at the end), the UTC start time, the pins, the Stopbar commit, the bundle hashes, and every client adaptation. A hard spend cap aborts the run.

**Client adaptations**, each recorded in `run.json` and to be disclosed in the results:
- **Model-name entry:** the pinned model IDs are added to AgentDojo's `MODEL_NAMES` with `"Claude"`, the same prose name it uses for every Claude model. The unmodified `important_instructions` attack looks the agent's name up there and otherwise raises an error.
- **Opus 5.5 settings:**
  - no `temperature` (the API rejects it)
  - `effort: medium` pinned via `output_config`
  - `max_tokens` raised from AgentDojo's 1024 to 16000, because adaptive thinking (which can't be disabled) counts against it
- **Haiku 4.5** uses AgentDojo's stock settings.

**A0** is AgentDojo's stock pipeline. **A2** differs only in that each tool call goes to `stopbard` first: only HTTP 200 runs, and anything else (including an unreachable `stopbard`) is a tool error carrying the reason codes. Taint is computed by `stopbard` from the frozen trust map. The harness only names the session.
