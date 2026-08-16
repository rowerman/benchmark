#!/bin/bash
set -euo pipefail
CHAIN="identity-trust"
echo "[identity-trust] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/iam-enum-oracle/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/golden-saml/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/actor-token/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/lowcode-secrets/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] identity-trust chain deployed (Chain-54)"
