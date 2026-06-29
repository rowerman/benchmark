#!/bin/bash
set -euo pipefail
CHAIN="s3-to-cf"
echo "[s3-to-cf] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-07 (s3-monopoly)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/s3-monopoly/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-05 (cf-injection)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cf-injection/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] s3-to-cf chain deployed"
echo "    Port: 11636"
echo "    See: docs/chains/s3-to-cf-exploitation.md"
