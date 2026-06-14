#!/bin/bash
set -euo pipefail
echo "[Chain-43] tearing down..."
cd "$(dirname "$0")"
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-07/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-15/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-16/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-43] cleaned"
