#!/bin/bash
set -euo pipefail
echo "[Chain-43] loggap-to-s3-stealth deploying..."
cd "$(dirname "$0")"
echo "  Starting cloud-16..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-16/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-15..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-15/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-07..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-07/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-43 deployed"
