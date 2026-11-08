#!/usr/bin/env bash
# make demo — product walking skeleton. Builds the binaries, then runs the
# scripted AgentKit journey on an Anvil fork of Base against stopbard started
# from a config file. DEV MODE, dev keys, stub data; no real funds. The Python
# driver (research/walletagent/demo.py) prints the journey, the gaps it exposes
# and the hidden-knowledge steps, and times the journey against the 30-min goal.
set -euo pipefail
cd "$(dirname "$0")/.."

t_build_start=$(date +%s)
echo "==> build (go build -o bin/) "
go build -o bin/stopbard ./cmd/stopbard
go build -o bin/stopbar ./cmd/stopbar
echo "    build took $(( $(date +%s) - t_build_start ))s"

if ! command -v anvil >/dev/null; then
  echo "demo needs Anvil (Foundry): https://getfoundry.sh  (brew install foundry)" >&2
  exit 1
fi

W=research/walletagent
if [[ ! -x "$W/.venv/bin/python" ]]; then
  echo "==> first run: creating the Python venv (this is the one-time setup the 30-min clock includes)"
  python3 -m venv "$W/.venv"
  "$W/.venv/bin/pip" -q install -r "$W/requirements.lock"
fi

exec "$W/.venv/bin/python" "$W/demo.py"
