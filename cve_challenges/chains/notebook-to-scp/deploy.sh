#!/bin/bash
set -euo pipefail
CHAIN="notebook-to-scp"
echo "[notebook-to-scp] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-07 (notebook-escape)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/notebook-escape/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-14 (cosmiss-notebook)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cosmiss-notebook/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-11 (scp-bypass)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/scp-bypass/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] notebook-to-scp chain deployed"
echo "    See: docs/chains/notebook-to-scp-exploitation.md"
