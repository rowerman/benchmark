#!/bin/bash
set -euo pipefail
CHAIN="cf-to-scp"
echo "[cf-to-scp] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-05..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-05/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-07..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-07/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-16..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-16/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-15..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-15/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] cf-to-scp chain deployed"
echo "    Port: 11641"
echo "    See: docs/chains/cf-to-scp-exploitation.md"
