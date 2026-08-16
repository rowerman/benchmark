#!/bin/bash
set -euo pipefail
CHAIN="managed-db-lateral"
echo "[managed-db-lateral] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/cloudsql-index-rce/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/rds-logfdw/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/extrareplica-repl/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] managed-db-lateral chain deployed (Chain-49)"
