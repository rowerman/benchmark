#!/bin/bash
set -euo pipefail
echo "[Chain-44] svctag-to-imds-to-deputy deploying..."
cd "$(dirname "$0")"
echo "  Starting cloud-18..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-18/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-01/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-17..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-17/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-44 deployed"
