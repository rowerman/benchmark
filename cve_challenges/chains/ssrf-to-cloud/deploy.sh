#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-32] SSRF to Cloud Credential Theft — 2 steps, Web→Cloud"

# Step 1: SSRF internal service (Docker)
echo "=== Step 1: WEB-10 SSRF Internal Service ==="
docker compose -f "$ROOT/docker/web/ssrf-internal/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSRF web app at http://localhost:10110"

# Step 2: EC2 SSRF / IMDS (Docker)
echo "=== Step 2: CLOUD-03 EC2 SSRF IMDS ==="
docker compose -f "$ROOT/docker/cloud/ssrf-imds/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] Cloud metadata simulator at http://localhost:10603"

echo ""
echo "[Chain-32] Ready"
echo "  Step 1: http://localhost:10110 → SSRF → flag{c32-step1-ssrf}"
echo "  Step 2: http://localhost:10603 → IMDS → flag{c32-step2-cloud}"
