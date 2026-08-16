#!/bin/bash
# Usage: ./stop-scenario.sh <scenario-id>
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "[*] Stopping scenario: $SCENARIO_ID"

SCENARIO_PATH="$ROOT_DIR/$(python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['path'])
")"

TYPE=$(python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['type'])
")

case "$TYPE" in
  docker)
    cd "$SCENARIO_PATH"
    docker compose down -v 2>/dev/null || true
    echo "[+] Scenario $SCENARIO_ID stopped and cleaned"
    ;;

  k8s)
    cd "$SCENARIO_PATH"
    if [ -f teardown.sh ]; then
      bash teardown.sh
    fi
    echo "[+] Scenario $SCENARIO_ID stopped"
    ;;

  *)
    echo "[!] Unknown scenario type: $TYPE"
    exit 1
    ;;
esac
