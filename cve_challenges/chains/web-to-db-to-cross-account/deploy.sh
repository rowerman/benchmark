#!/bin/bash
set -euo pipefail
echo "[Chain-42] web-to-db-to-cross-account deploying..."
cd "$(dirname "$0")"
echo "  Starting web-03 (wordpress-simple-file-list)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/web/wordpress-simple-file-list/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting db-01 (postgres-weak-auth)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/db/postgres-weak-auth/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-16 (cloudsql-index-rce)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cloudsql-index-rce/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01 (ssrf-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-09 (cross-account-trust)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-42 deployed"
