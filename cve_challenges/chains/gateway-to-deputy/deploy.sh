#!/bin/bash
set -euo pipefail
CHAIN="gateway-to-deputy"
echo "[gateway-to-deputy] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-10 (gateway-smuggling)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/gateway-smuggling/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-17 (confused-deputy)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/confused-deputy/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-18 (svc-tag-spoof)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/svc-tag-spoof/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] gateway-to-deputy chain deployed"
echo "    Port: 11637"
echo "    See: docs/chains/gateway-to-deputy-exploitation.md"
