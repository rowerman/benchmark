#!/bin/bash
set -euo pipefail
CHAIN="ssrf-to-oidc"
echo "[ssrf-to-oidc] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-01..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-01/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-11..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-11/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] ssrf-to-oidc chain deployed"
echo "    Port: 11639"
echo "    See: docs/chains/ssrf-to-oidc-exploitation.md"
