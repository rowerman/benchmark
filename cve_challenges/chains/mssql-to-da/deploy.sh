#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain 9] MSSQL Linked Server to Domain Admin — 4 steps, Web→DB→AD"

# Step 1-2: MSSQL containers (Docker)
echo "=== Steps 1-2: MSSQL xp_cmdshell + Linked Server ==="
docker compose -f "$ROOT/docker/web/mssql-xp-cmdshell/docker-compose.yml" up -d --build 2>&1 | tail -2
docker compose -f "$ROOT/docker/db/mssql-linked-server/docker-compose.yml" up -d 2>&1 | tail -2
echo "  [+] MSSQL web at localhost:3003 | Linked servers at 1433+1434"

# Step 3-4: AD (Docker Samba AD DC)
echo "=== Steps 3-4: AD PTH → DCSync ==="
AD_COMPOSE="$ROOT/ad/docker-compose.yml"
if ! docker ps --format '{{.Names}}' | grep -q ad-dc01; then
  echo "  [*] Starting Samba AD DC..."
  docker compose -f "$AD_COMPOSE" up -d --build 2>&1 | tail -2
  sleep 15
fi
echo "  [+] AD DC at 192.168.100.10"
echo ""
echo "[Chain 9] Ready"
echo "  Step 1: SQLi → xp_cmdshell → flag{chain9-step1-mssql}"
echo "  Step 2: sp_addlinkedsrvlogin → OPENQUERY chain → flag{chain9-step2-linked}"
echo "  Step 3: Pass-the-Hash → flag{chain9-step3-pth}"
echo "  Step 4: DCSync → flag{chain9-step4-dcsync-final}"
