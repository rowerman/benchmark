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

  vagrant)
    cd "$SCENARIO_PATH"
    echo "[+] Starting VM..."
    echo "[+] Flag: $FLAG"
    # Try QEMU first (works without VirtualBox), fallback to Vagrant
    if [ -f qemu.sh ]; then
      echo "[+] Using QEMU TCG mode (no KVM required)"
      echo "[+] Run: cd $SCENARIO_PATH && bash qemu.sh"
    elif command -v vagrant &>/dev/null; then
      vagrant up
      echo "[+] Scenario $SCENARIO_ID started (Vagrant)"
    else
      echo "[!] No VM runtime available. Options:"
      echo "[!]   QEMU: cd $SCENARIO_PATH && bash qemu.sh"
      echo "[!]   Vagrant: install VirtualBox, then vagrant up"
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

  samba-ad)
    echo "[+] Starting Samba AD DC (shared Docker container)..."
    AD_COMPOSE="$ROOT_DIR/ad/docker-compose.yml"
    if docker ps --format '{{.Names}}' | grep -q ad-dc01; then
      echo "[+] AD DC already running"
    else
      docker compose -f "$AD_COMPOSE" up -d --build 2>&1 | tail -3
      echo "[*] Waiting for AD provisioning (~60s)..."
      sleep 15
    fi
    echo "[+] AD DC at 192.168.100.10, domain: north.sevenkingdoms.local"
    echo "[+] Scenario $SCENARIO_ID ready (Samba AD)"
    ;;

  ad)
    echo "[*] AD scenario (Windows-Only) — requires GOAD + VirtualBox/Windows Server"
    echo "[!] Platform: windows-only — not deployable on this host"
    echo "[+] Config at: $SCENARIO_PATH/config.yaml"  ;;

  *)
    echo "[!] Unknown scenario type: $TYPE"
    exit 1
    ;;
esac
