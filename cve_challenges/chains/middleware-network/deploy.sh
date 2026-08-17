#!/bin/bash
set -euo pipefail
CHAIN="middleware-network"
echo "[middleware-network] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/omigod-agent/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/shared-nat/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/synlapse-ir/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] middleware-network chain deployed (Chain-52)"
