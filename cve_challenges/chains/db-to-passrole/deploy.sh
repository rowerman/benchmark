#!/bin/bash
set -euo pipefail
CHAIN="db-to-passrole"
echo "[db-to-passrole] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-06..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-06/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-14..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-14/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] db-to-passrole chain deployed"
echo "    Port: 11640"
echo "    See: docs/chains/db-to-passrole-exploitation.md"
