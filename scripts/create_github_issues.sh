#!/usr/bin/env bash
# Creates milestones (phases), labels (epics) and one issue per task from docs/tasks.csv.
# Usage: gh auth login && ./scripts/create_github_issues.sh <owner>/<repo>
# Idempotent-ish: skips issues whose title already exists.
set -euo pipefail
REPO="${1:?usage: $0 owner/repo}"
cd "$(dirname "$0")/.."

python3 - "$REPO" <<'PY'
import csv, json, subprocess, sys
repo = sys.argv[1]
PH = {"P0":"Phase 0 - Foundations","P1":"Phase 1 - Agent-wallet MVP","P2":"Phase 2 - Corpus & community",
      "P3":"Phase 3 - Code-mode agents","P4":"Phase 4 - Custody grade"}
THIN = set()
for line in open("docs/TASKS.md"):
    if line.startswith("**Thin slice"):
        THIN = {x.strip() for x in line.split("—")[1].split(",")}

def gh(*args, check=True):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=check).stdout

existing_ms = {m["title"]: m["number"] for m in json.loads(gh("api", f"repos/{repo}/milestones?state=all&per_page=100"))}
for title in PH.values():
    if title not in existing_ms:
        m = json.loads(gh("api", f"repos/{repo}/milestones", "-f", f"title={title}"))
        existing_ms[title] = m["number"]

rows = list(csv.DictReader(open("docs/tasks.csv")))
for label in sorted({r["epic"] for r in rows} | {"thin-slice"}):
    gh("label", "create", label, "--repo", repo, "--force", "--color", "0E8A16" if label == "thin-slice" else "1D76DB")

existing = {i["title"] for i in json.loads(gh("issue", "list", "--repo", repo, "--state", "all", "--limit", "500", "--json", "title"))}
for r in rows:
    title = f"{r['id']}: {r['title']}"
    if title in existing:
        continue
    body = (f"**Detail**\n{r['detail']}\n\n**Acceptance criteria**\n- [ ] {r['acceptance']}\n\n"
            f"**Estimate:** {r['est_days']}d  \n**Depends on:** {r['depends'] or '-'}  \n**Refs:** {r['refs'] or '-'}\n")
    labels = [r["epic"]] + (["thin-slice"] if r["id"] in THIN else [])
    args = ["issue", "create", "--repo", repo, "--title", title, "--body", body, "--milestone", PH[r["phase"]]]
    for l in labels: args += ["--label", l]
    print(gh(*args).strip())
PY
