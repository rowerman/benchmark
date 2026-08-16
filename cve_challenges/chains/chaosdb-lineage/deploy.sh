#!/bin/bash
set -euo pipefail
CHAIN="chaosdb-lineage"
echo "[chaosdb-lineage] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cosmiss-notebook/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/wireserver-bootstrap/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/attachme-volume/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] chaosdb-lineage chain deployed (Chain-50)"
