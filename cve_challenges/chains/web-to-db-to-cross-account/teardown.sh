#!/bin/bash
set -euo pipefail
echo "[Chain-42] tearing down..."
cd "$(dirname "$0")"
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-12/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-01/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/cloud-06/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/db-01/docker-compose.yml down -v 2>/dev/null || true
docker compose -f /home/kianabin/benchmark_design/benchmarks/cve_challenges/docker/cloud/web-03/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-42] cleaned"
