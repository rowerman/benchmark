#!/bin/bash
# Usage: ./start-scenario.sh <scenario-id>
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Generate the flags declared by this scenario for this run.
FLAG_NAMES=()
FLAG_SUFFIXES=()
case "$SCENARIO_ID" in
  cloud-13)
    FLAG_NAMES=(HOST_READ INTERNAL_API)
    FLAG_SUFFIXES=(host-read internal-api)
    ;;
  cloud-17)
    FLAG_NAMES=(BOOTSTRAP NODE_SECRETS)
    FLAG_SUFFIXES=(bootstrap node-secrets)
    ;;
esac

if [ "${#FLAG_NAMES[@]}" -eq 0 ]; then
  FLAG=$(python3 "$SCRIPT_DIR/flag_manager.py" "$SCENARIO_ID")
  export CVE_FLAG="$FLAG"
else
  for i in "${!FLAG_NAMES[@]}"; do
    flag=$(python3 "$SCRIPT_DIR/flag_manager.py" "${SCENARIO_ID}-${FLAG_SUFFIXES[$i]}")
    export "CVE_FLAG_${FLAG_NAMES[$i]}=$flag"
  done
fi

echo "[*] Starting scenario: $SCENARIO_ID"
if [ "${#FLAG_NAMES[@]}" -eq 0 ]; then
  echo "[+] Flag: $FLAG"
else
  for name in "${FLAG_NAMES[@]}"; do
    env_name="CVE_FLAG_${name}"
    printf '[+] Flag (%s): %s\n' "$(echo "$name" | tr '_' '-' | tr '[:upper:]' '[:lower:]')" "${!env_name}"
  done
fi

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
    if [ "${#FLAG_NAMES[@]}" -eq 0 ]; then
      echo "CVE_FLAG=$FLAG" > .env
    else
      : > .env
      for name in "${FLAG_NAMES[@]}"; do
        env_name="CVE_FLAG_${name}"
        printf '%s=%s\n' "$env_name" "${!env_name}" >> .env
      done
    fi
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
    if [ "${#FLAG_NAMES[@]}" -eq 0 ]; then
      echo "[+] Flag: $FLAG"
    else
      for name in "${FLAG_NAMES[@]}"; do
        env_name="CVE_FLAG_${name}"
        printf '[+] Flag (%s): %s\n' "$(echo "$name" | tr '_' '-' | tr '[:upper:]' '[:lower:]')" "${!env_name}"
      done
    fi
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
