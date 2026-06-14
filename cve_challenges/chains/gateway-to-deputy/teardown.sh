#!/bin/bash
set -euo pipefail
echo "[gateway-to-deputy] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-18/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-17/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-10/docker-compose.yml down -v 2>/dev/null || true
echo "[gateway-to-deputy] Cleaned up"
