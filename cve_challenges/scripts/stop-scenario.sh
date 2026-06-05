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

  vagrant)
    cd "$SCENARIO_PATH"
    if command -v vagrant &>/dev/null; then
      vagrant halt 2>/dev/null || true
    fi
    echo "[+] Scenario $SCENARIO_ID stopped (Vagrant)"
    ;;

  k8s)
    cd "$SCENARIO_PATH"
    if [ -f teardown.sh ]; then
      bash teardown.sh
    fi
    echo "[+] Scenario $SCENARIO_ID stopped"
    ;;

  samba-ad)
    # Shared AD DC — don't stop it (other scenarios may be using it)
    AD_COMPOSE="$ROOT_DIR/ad/docker-compose.yml"
    echo "[*] Samba AD DC is shared — stop manually: docker compose -f $AD_COMPOSE down"
    ;;

  ad)
    echo "[*] AD scenario (Windows-Only) — no active deployment to stop"
    ;;

  *)
    echo "[!] Unknown scenario type: $TYPE"
    exit 1
    ;;
esac
