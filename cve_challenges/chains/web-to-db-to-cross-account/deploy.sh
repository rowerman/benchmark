#!/bin/bash
set -euo pipefail
echo "[Chain-42] web-to-db-to-cross-account deploying..."
cd "$(dirname "$0")"
echo "  Starting web-03..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/web-03/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting db-01..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/db-01/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-06..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-06/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-01..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-01/docker-compose.yml up -d --build 2>&1 | tail -2
echo "  Starting cloud-12..."
CVE_FLAG="flag{chain-test}" docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-12/docker-compose.yml up -d --build 2>&1 | tail -2
echo "[+] Chain-42 deployed"
