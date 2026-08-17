#!/bin/bash
set -euo pipefail
CHAIN="db-to-cross-account"
echo "[db-to-cross-account] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-25 (cloudsql-index-rce)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/cloudsql-index-rce/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01 (ssrf-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] db-to-cross-account chain deployed"
echo "    See: docs/chains/db-to-cross-account-exploitation.md"
