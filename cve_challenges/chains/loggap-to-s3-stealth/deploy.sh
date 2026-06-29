#!/bin/bash
set -euo pipefail
echo "[Chain-43] loggap-to-s3-stealth deploying..."
cd "$(dirname "$0")"
echo "  Starting cloud-16 (logging-gap)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/logging-gap/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-15 (scp-bypass)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/scp-bypass/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-07 (s3-monopoly)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../docker/cloud/s3-monopoly/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-43 deployed"
