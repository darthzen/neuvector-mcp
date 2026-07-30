#!/usr/bin/env bash
# Create the GitHub Project (v2) board for this build and put all 34 tickets on
# it, then point build-plan/config.yaml at it.
#
# Run from the repo root:  bash build-plan/create-board.sh
set -euo pipefail

OWNER=darthzen
REPO=darthzen/neuvector-mcp
TITLE="NeuVector MCP"

echo "==> creating project board '$TITLE'"
NUM=$(gh project create --owner "$OWNER" --title "$TITLE" --format json \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["number"])')
echo "    project number: $NUM"

echo "==> adding 34 tickets"
gh issue list --repo "$REPO" --state all --limit 100 --json url --jq '.[].url' \
  | sort -t/ -k7 -n \
  | while read -r url; do
      gh project item-add "$NUM" --owner "$OWNER" --url "$url" >/dev/null
      echo "    + $url"
    done

echo "==> wiring build-plan/config.yaml"
python3 - "$NUM" <<'PY'
import re, sys
num = sys.argv[1]
p = "build-plan/config.yaml"
s = open(p).read()
s = s.replace("  build_through: M11",
              f"  project_number: {num}        # GitHub Project (v2) board\n  build_through: M11")
s = re.sub(r"  board_status: false.*", "  board_status: true       # push Status to the board on start/finish", s)
open(p, "w").write(s)
print(open(p).read())
PY

echo
echo "Board ready: https://github.com/users/$OWNER/projects/$NUM"
echo "Commit the config change when you're happy with it."
