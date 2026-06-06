#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-34] XXE SVG to Elasticsearch Data Exfiltration — 2 steps, Web→DB"

# Step 1: XXE SVG upload (Docker)
echo "=== Step 1: WEB-14 XXE SVG Upload ==="
docker compose -f "$ROOT/docker/web/xxe-svg/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] XXE SVG web app at http://localhost:10114"

# Step 2: Elasticsearch script injection (Docker)
echo "=== Step 2: DB-07 Elasticsearch Script Injection ==="
docker compose -f "$ROOT/docker/db/elasticsearch-script/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] Elasticsearch at http://localhost:10207"

echo ""
echo "[Chain-34] Ready"
echo "  Step 1: http://localhost:10114 → upload SVG with XXE → flag{c34-step1-xxe}"
echo "  Step 2: http://localhost:10207 → Painless script → flag{c34-step2-es}"
