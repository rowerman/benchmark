#!/bin/bash
set -euo pipefail
CHAIN="s3-to-cf"
echo "[s3-to-cf] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-07..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-07/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-05..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-05/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] s3-to-cf chain deployed"
echo "    Port: 11636"
echo "    See: docs/chains/s3-to-cf-exploitation.md"
