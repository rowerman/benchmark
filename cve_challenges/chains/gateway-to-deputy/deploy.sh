#!/bin/bash
set -euo pipefail
CHAIN="gateway-to-deputy"
echo "[gateway-to-deputy] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-30 (shared-nat)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/shared-nat/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-29 (lowcode-secrets)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/lowcode-secrets/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-09 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] gateway-to-deputy chain deployed"
echo "    See: docs/chains/gateway-to-deputy-exploitation.md"
