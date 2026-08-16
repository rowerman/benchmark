#!/bin/bash
# Usage: ./start-scenario.sh <scenario-id>
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Generate a random flag for this run
FLAG=$(python3 "$SCRIPT_DIR/flag_manager.py" "$SCENARIO_ID")
export CVE_FLAG="$FLAG"

echo "[*] Starting scenario: $SCENARIO_ID"
echo "[+] Flag: $FLAG"

# Determine scenario type from registry
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
    echo "[+] Starting Docker Compose..."
    # Write the dynamic flag to .env for docker compose variable substitution
    echo "CVE_FLAG=$FLAG" > .env
    # Write the dynamic flag to any host flag.txt file (used by volume-mount scenarios)
    if [ -f flag.txt ]; then
      echo "$FLAG" > flag.txt
    fi
    # Also check subdirectories for flag.txt (e.g., app/flag.txt)
    for f in */flag.txt; do
      [ -f "$f" ] && echo "$FLAG" > "$f"
    done 2>/dev/null || true
    # For database scenarios with init.sql using __CVE_FLAG__ placeholder:
    # The Dockerfile.db handles substitution at build time via ARG CVE_FLAG.
    # We do NOT sed init.sql here — that would modify the source file permanently.
    if [ -f docker-compose.yml ]; then
      docker compose up -d --build
    elif [ -f docker-compose.yaml ]; then
      docker compose up -d --build
    fi
    echo "[+] Scenario $SCENARIO_ID started (Docker)"
    echo "[+] Flag: $FLAG"
    ;;

  k8s)
    cd "$SCENARIO_PATH"
    echo "[+] Starting K8s scenario..."
    if [ -f deploy.sh ]; then
      bash deploy.sh
    else
      echo "[!] deploy.sh not found in $SCENARIO_PATH"
      exit 1
    fi
    echo "[+] Scenario $SCENARIO_ID started (K8s)"
    echo "[+] Flag: $FLAG"
    ;;

  *)
    echo "[!] Unknown scenario type: $TYPE"
    exit 1
    ;;
esac
