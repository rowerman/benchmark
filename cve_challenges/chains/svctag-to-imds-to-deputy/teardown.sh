#!/bin/bash
set -euo pipefail
echo "[Chain-44] tearing down..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/shared-nat/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-44] cleaned"
