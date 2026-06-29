#!/bin/bash
set -euo pipefail
echo "[Chain-42] web-to-db-to-cross-account deploying..."
cd "$(dirname "$0")"
echo "  Starting web-03 (wordpress-simple-file-list)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/web/wordpress-simple-file-list/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting db-01 (postgres-weak-auth)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/db/postgres-weak-auth/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-06 (db-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/db-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01 (ssrf-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-42 deployed"
