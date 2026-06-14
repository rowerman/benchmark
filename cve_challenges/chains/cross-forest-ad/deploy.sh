#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-40] Web to Cross-Forest Domain Admin — 5 steps, Web→Linux→AD×3"

# Step 1: SSTI Jinja2 (Docker)
echo "=== Step 1: WEB-12 SSTI Jinja2 ==="
docker compose -f "$ROOT/docker/web/ssti-jinja2/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSTI web app at http://localhost:10112"

# Step 2: Docker Socket Abuse (Docker)
echo "=== Step 2: LNX-08 Docker Socket ==="
docker compose -f "$ROOT/docker/linux/docker-socket/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSH at localhost:10303 (attacker:password123)"

# Steps 3-5: Shared AD DC (must already be running)
echo "=== Steps 3-5: AD DC ==="
echo "  [*] Ensure AD DC is running: cd ../../ad && docker compose up -d --build"
echo "  [+] AD DC at 192.168.100.10 (NORTH)"

echo ""
echo "[Chain-40] Ready (requires AD DC for steps 3-5)"
echo "  Step 1: http://localhost:10112 → SSTI RCE → flag{c40-step1-ssti}"
echo "  Step 2: ssh attacker@localhost -p 10303 → docker.sock → flag{c40-step2-docker}"
echo "  Step 3: Kerberoasting in NORTH → flag{c40-step3-kerberoast}"
echo "  Step 4: Cross-Forest Trust → SOUTH → flag{c40-step4-crossforest}"
echo "  Step 5: DCSync in SOUTH → flag{c40-step5-dcsync-final}"
