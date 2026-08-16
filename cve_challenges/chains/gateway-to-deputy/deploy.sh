#!/bin/bash
set -euo pipefail
CHAIN="gateway-to-deputy"
echo "[gateway-to-deputy] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-39 (shared-nat)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/shared-nat/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-38 (lowcode-secrets)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/lowcode-secrets/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] gateway-to-deputy chain deployed"
echo "    See: docs/chains/gateway-to-deputy-exploitation.md"
