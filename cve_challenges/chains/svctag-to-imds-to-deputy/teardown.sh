#!/bin/bash
set -euo pipefail
echo "[Chain-44] tearing down..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/shared-nat/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-44] cleaned"
