#!/bin/bash
set -euo pipefail
CHAIN="ssrf-to-oidc"
echo "[ssrf-to-oidc] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-01 (ssrf-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-08 (oidc-federation)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/oidc-federation/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-09 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] ssrf-to-oidc chain deployed"
echo "    Port: 11639"
echo "    See: docs/chains/ssrf-to-oidc-exploitation.md"
