#!/bin/bash
set -euo pipefail
CHAIN="detection-blindspot"
echo "[detection-blindspot] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/resource-explorer/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/iam-enum-oracle/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/beta-endpoint/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/persistence-as-a-service/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] detection-blindspot chain deployed (Chain-55)"
