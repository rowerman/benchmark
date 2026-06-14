#!/bin/bash
set -euo pipefail
CHAIN="ci-to-oidc"
echo "[ci-to-oidc] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-08..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-08/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-11..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-11/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-16..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloud-16/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] ci-to-oidc chain deployed"
echo "    Port: 11634"
echo "    See: docs/chains/ci-to-oidc-exploitation.md"
