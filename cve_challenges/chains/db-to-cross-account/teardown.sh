#!/bin/bash
set -euo pipefail
echo "[db-to-cross-account] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
echo "[db-to-cross-account] Cleaned up"
