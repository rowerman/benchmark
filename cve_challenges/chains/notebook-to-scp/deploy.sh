#!/bin/bash
set -euo pipefail
CHAIN="notebook-to-scp"
echo "[notebook-to-scp] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-09 (notebook-escape)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/notebook-escape/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-17 (confused-deputy)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/confused-deputy/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-16 (logging-gap)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/logging-gap/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] notebook-to-scp chain deployed"
echo "    Port: 11638"
echo "    See: docs/chains/notebook-to-scp-exploitation.md"
