#!/bin/bash
set -euo pipefail
CHAIN="ai-serverless-identity"
echo "[ai-serverless-identity] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/pickle-model/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/serverless-sa/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/actor-token/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] ai-serverless-identity chain deployed (Chain-51)"
