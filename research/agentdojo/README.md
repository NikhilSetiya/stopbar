# AgentDojo pilot harness (CS-503)

The protocol is [`PILOT.md`](PILOT.md), the pre-registration. The frozen policy bundle is in [`policies/banking/`](policies/banking/FREEZE.md).

```bash
cd research/agentdojo
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock   # agentdojo==0.1.35 + pinned deps
.venv/bin/python -m unittest discover -s tests                        # harness unit tests

# stopbard with the frozen bundle (from the repo root, in another terminal):
#   echo '{"limits_disabled": true}' > /tmp/world.json
#   stopbard -listen 127.0.0.1:7777 -dev-world /tmp/world.json -policies research/agentdojo/policies/banking -state-dir /tmp/pilot-state

.venv/bin/python -m harness.run --dry-run --out results/                     # free: scripted ground-truth agent, no API
.venv/bin/python -m harness.run --model claude-haiku-4-5 --cap-usd 20 --out results/   # the pilot (PAID), both arms interleaved
.venv/bin/python -m harness.run --resume results/<run dir>                   # after a quota or infrastructure stop
.venv/bin/python -m harness.analyze results/<run dir>
```

The runner refuses to start if:
- the AgentDojo version differs from the pin
- A2's `stopbard` enforces any bundle other than the frozen hash
- the bundle directory has uncommitted changes

Before the first episode it writes `run.json`: the requested model ID (the model versions the API reports back are added per run segment), the UTC start time, the pins, the Stopbar commit, the bundle hashes, and every client adaptation. A hard spend cap aborts the run.

**The pilot model** is `claude-haiku-4-5` with a $20 cap across the whole run (PILOT Amendment 3.2). Gemini Flash on the free tier was evaluated and not taken (Amendment 4). Keys come from the macOS keychain (`security add-generic-password -s stopbar-anthropic-key -a "$USER" -w`; Gemini: `stopbar-gemini-key`) and are never logged.
- **Interleaved and atomic:** each user task runs benign A0, benign A2, then attacked A0 and A2. A task counts only once both arms finish it. A stopped run discards the unfinished task, and `--resume` reruns it.
- **Infrastructure is not a result:** rate limits, overloads, 5xx, timeouts and network errors are retried with backoff inside the client (SDK retries off; logged to `infra.jsonl`). Exhausted retries, a quota or the spend cap stops the run with exit code 3, and the run can be resumed.
- **Pinned model:** the run stops if the API reports a model other than the pin.
- **`anthropic==1.17.0`:** AgentDojo 0.1.35's Anthropic element crashes on SDK 2.x, which made `MessageParam` a `Union`.

**Client adaptations**, each recorded in `run.json` and to be disclosed in the results:
- **Model-name entry:** the pinned model ID is added to AgentDojo's `MODEL_NAMES` with the prose AgentDojo uses for its family: `"AI model developed by Google"` for Gemini, `"Claude"` for Claude. The unmodified `important_instructions` attack looks the agent's name up there and otherwise raises an error.
- **Gemini thought signatures:** model turns are sent back verbatim. Gemini 3 rejects function-call turns without their `thought_signature` (HTTP 400), and the stock element drops it. Otherwise Gemini uses the stock settings: temperature 0.0, 65535 max tokens.
- **Opus 5.5 settings** (three-arm run):
  - no `temperature` (the API rejects it)
  - `effort: medium` pinned via `output_config`
  - `max_tokens` raised from AgentDojo's 1024 to 16000
- **Haiku 4.5** uses AgentDojo's stock settings. The Anthropic models are metered against `--cap-usd`.

**A0** is AgentDojo's stock pipeline. **A2** differs only in that each tool call goes to `stopbard` first: only HTTP 200 runs, and anything else (including an unreachable `stopbard`) is a tool error carrying the reason codes. Taint is computed by `stopbard` from the frozen trust map. The harness only names the session.
