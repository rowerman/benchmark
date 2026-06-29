#!/bin/bash
set -euo pipefail
echo "[Chain-44] svctag-to-imds-to-deputy deploying..."
cd "$(dirname "$0")"
echo "  Starting cloud-18 (svc-tag-spoof)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/svc-tag-spoof/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01 (ssrf-to-imds)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/ssrf-to-imds/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-17 (confused-deputy)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/confused-deputy/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-44 deployed"
