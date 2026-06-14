#!/bin/bash
set -euo pipefail
CHAIN="lambda-to-cross-account"
echo "[lambda-to-cross-account] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-04..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-04/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-14..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-14/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] lambda-to-cross-account chain deployed"
echo "    Port: 11633"
echo "    See: docs/chains/lambda-to-cross-account-exploitation.md"
