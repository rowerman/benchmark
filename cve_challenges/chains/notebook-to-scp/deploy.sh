#!/bin/bash
set -euo pipefail
CHAIN="notebook-to-scp"
echo "[notebook-to-scp] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-09..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-09/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-17..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-17/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-16..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-16/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] notebook-to-scp chain deployed"
echo "    Port: 11638"
echo "    See: docs/chains/notebook-to-scp-exploitation.md"
