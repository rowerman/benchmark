#!/bin/bash
set -euo pipefail
CHAIN="db-to-cross-account"
echo "[db-to-cross-account] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-06..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-06/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] db-to-cross-account chain deployed"
echo "    Port: 11635"
echo "    See: docs/chains/db-to-cross-account-exploitation.md"
