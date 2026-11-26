#!/usr/bin/env bash
# Regenerate docs/quickstart.gif (CS-198): a real terminal recording of
# scripts/quickstart.sh (the README quickstart block, verbatim), recorded with
# asciinema 2.4.0 and rendered with agg 1.9.0, both exact pins (agg checksum-
# verified). The run's real output is paced line by line so it can be read
# (scripts/record_pace.py); nothing is edited or staged. Needs what
# quickstart.sh needs (anvil, cast) plus network for the
# first download. Usage: scripts/record_quickstart.sh
set -euo pipefail
cd "$(dirname "$0")/.."
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  AGG=agg-aarch64-apple-darwin      SUM=742b2b6230529b72f310acb835e9479496000f2eabc97b0993cabe1d7fe70171 ;;
  Linux-x86_64)  AGG=agg-x86_64-unknown-linux-gnu  SUM=f111e315cd71056b116302342553dd765b7297579ed511f111d0cedb442aeda6 ;;
  *) echo "record_quickstart: no pinned agg checksum for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
curl -fsSL -o "$T/agg" "https://github.com/asciinema/agg/releases/download/v1.9.0/$AGG"
echo "$SUM  $T/agg" | shasum -a 256 -c - >/dev/null
chmod +x "$T/agg"
python3 -m venv "$T/venv" && "$T/venv/bin/pip" -q install asciinema==2.4.0
go build -o "$T/" ./cmd/stopbard ./cmd/stopbar
"$T/venv/bin/asciinema" rec --quiet --overwrite --cols 120 --rows 36 \
  --command "bash -c './scripts/quickstart.sh $T/stopbard $T/stopbar 2>&1 | python3 -u scripts/record_pace.py'" "$T/quickstart.cast"
"$T/agg" --idle-time-limit 1.5 --speed 1.5 --font-size 10 --fps-cap 4 --last-frame-duration 5 "$T/quickstart.cast" docs/quickstart.gif
ls -l docs/quickstart.gif
