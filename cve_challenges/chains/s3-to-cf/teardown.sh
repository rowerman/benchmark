#!/bin/bash
set -euo pipefail
echo "[s3-to-cf] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cf-injection/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/global-s3-squatting/docker-compose.yml down -v 2>/dev/null || true
echo "[s3-to-cf] Cleaned up"
