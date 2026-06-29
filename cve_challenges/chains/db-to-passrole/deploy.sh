#!/bin/bash
set -euo pipefail
CHAIN="db-to-passrole"
echo "[db-to-passrole] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-06 (db-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/db-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-14 (passrole-abuse)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/passrole-abuse/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] db-to-passrole chain deployed"
echo "    Port: 11640"
echo "    See: docs/chains/db-to-passrole-exploitation.md"
