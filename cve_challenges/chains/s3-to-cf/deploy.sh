#!/bin/bash
set -euo pipefail
CHAIN="s3-to-cf"
echo "[s3-to-cf] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-13 (global-s3-squatting)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/global-s3-squatting/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-05 (cf-injection)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cf-injection/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-09 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] s3-to-cf chain deployed"
echo "    See: docs/chains/s3-to-cf-exploitation.md"
