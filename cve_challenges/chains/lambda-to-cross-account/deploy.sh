#!/bin/bash
set -euo pipefail
CHAIN="lambda-to-cross-account"
echo "[lambda-to-cross-account] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-04 (lambda-passrole)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/lambda-passrole/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-34 (iam-enum-oracle)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/iam-enum-oracle/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] lambda-to-cross-account chain deployed"
echo "    See: docs/chains/lambda-to-cross-account-exploitation.md"
