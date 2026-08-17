#!/bin/bash
set -euo pipefail
CHAIN="ci-to-oidc"
echo "[ci-to-oidc] Deploying chain..."
cd "$(dirname "$0")"
echo "  Starting cloud-08 (ci-poisoning)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/ci-poisoning/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-11 (oidc-federation)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/oidc-federation/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2

echo "[+] ci-to-oidc chain deployed"
echo "    See: docs/chains/ci-to-oidc-exploitation.md"
