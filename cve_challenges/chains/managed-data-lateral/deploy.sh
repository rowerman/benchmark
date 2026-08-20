#!/bin/bash
set -euo pipefail
CHAIN="managed-data-lateral"
echo "[managed-data-lateral] Deploying chain..."
cd "$(dirname "$0")"
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/synlapse-ir/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/dataform-pt/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/cloudsql-index-rce/docker-compose.yml up -d --build 2>&1 | tail -2
CVE_FLAG="flag{chain-test}" docker compose -f ../../scenarios/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] managed-data-lateral chain deployed (Chain-56)"
