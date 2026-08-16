#!/bin/bash
set -euo pipefail
CHAIN="cf-to-scp"
echo "[cf-to-scp] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-05 (cf-injection)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cf-injection/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-21 (global-s3-squatting)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/global-s3-squatting/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-15 (scp-bypass)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/scp-bypass/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] cf-to-scp chain deployed"
echo "    See: docs/chains/cf-to-scp-exploitation.md"
