#!/bin/bash
set -euo pipefail
CHAIN="supply-chain-persistence"
echo "[supply-chain-persistence] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/buildfleet-registry/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/composer-depconf/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/persistence-as-a-service/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] supply-chain-persistence chain deployed (Chain-53)"
