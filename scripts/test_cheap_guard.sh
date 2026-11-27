#!/usr/bin/env bash
# Tests the cheap-guard workflow's script (.github/workflows/cheap-guard.yml)
# against a stubbed `gh`: which branches are restricted, which paths are
# protected, renames, an incomplete file list, and a hostile branch name.
set -uo pipefail
cd "$(dirname "$0")/.."
S="$(mktemp -d)"; trap 'rm -rf "$S"' EXIT
mkdir -p "$S/bin"
python3 -c "import yaml; print(yaml.safe_load(open('.github/workflows/cheap-guard.yml'))['jobs']['cheap-guard']['steps'][0]['run'])" >"$S/run.sh"
printf '#!/bin/sh\ncat "$FAKE_FILES"\n' >"$S/bin/gh"; chmod +x "$S/bin/gh"
T=$'\t' fails=0
t() { # name branch changed_files want_fail files...
  local name=$1 br=$2 ch=$3 want=$4; shift 4
  printf '%s\n' "$@" >"$S/files"
  (cd "$S" && PATH="$S/bin:$PATH" FAKE_FILES="$S/files" HEAD_REF="$br" PR=1 REPO=x/y CHANGED="$ch" bash run.sh >out 2>&1)
  local failed=$(( $? != 0 ))
  if [[ $failed -eq $want ]]; then echo "ok   $name"; else echo "FAIL $name"; cat "$S/out"; fails=1; fi
}
t "normal branch may touch internal/"         feature/x  1 0 "internal/engine/engine.go$T"
t "cheap/ docs-only passes"                   cheap/docs 2 0 "README.md$T" "docs/LLD.md$T"
t "cheap/ examples/ outside policies passes"  cheap/x    1 0 "examples/quickstart/agent.py$T"
t "cheap/ internal/ fails"                    cheap/x    1 1 "internal/limiter/limiter.go$T"
t "cheap/ spec/ fails"                        cheap/x    1 1 "spec/approval-signature-v1.md$T"
t "cheap/ corpus/ fails"                      cheap/x    1 1 "corpus/attacks/a.yaml$T"
t "cheap/ examples/policies/ fails"           cheap/x    1 1 "examples/policies/starter.cedar$T"
t "cheap/ .github/workflows/ (the guard) fails" cheap/x  1 1 ".github/workflows/cheap-guard.yml$T"
t "cheap/ rename out of internal/ fails"      cheap/x    1 1 "docs/moved.go${T}internal/engine/engine.go"
t "Cheap/ is restricted too (case)"           Cheap/x    1 1 "internal/x.go$T"
t "cheapskate/ is not cheap/"                 cheapskate/x 1 0 "internal/x.go$T"
t "incomplete file list fails closed"         cheap/x    5 1 "README.md$T"
t "hostile branch name is data, not code"     'cheap/$(touch pwned)' 1 0 "README.md$T"
if [[ -e "$S/pwned" ]]; then echo "FAIL branch name was executed"; fails=1; fi
exit $fails
