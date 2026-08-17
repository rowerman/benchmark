#!/bin/bash
set -euo pipefail
echo "[Chain-43] loggap-to-s3-stealth deploying..."
cd "$(dirname "$0")"
echo "  Starting cloud-34 (iam-enum-oracle)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/iam-enum-oracle/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-35 (beta-endpoint)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/beta-endpoint/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-21 (global-s3-squatting)..."
CVE_FLAG="flag{chain-test}" docker compose -f ../scenarios/cloud/global-s3-squatting/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-43 deployed"
