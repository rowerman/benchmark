#!/bin/bash
set -euo pipefail
echo "[s3-to-cf] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-12/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-05/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-07/docker-compose.yml down -v 2>/dev/null || true
echo "[s3-to-cf] Cleaned up"
