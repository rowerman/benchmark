#!/bin/bash
set -euo pipefail
echo "[Chain-44] tearing down..."
cd "$(dirname "$0")"
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-17/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-01/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-18/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-44] cleaned"
