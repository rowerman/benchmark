#!/bin/bash
set -euo pipefail
echo "[cf-to-scp] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-15/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-16/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-07/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-05/docker-compose.yml down -v 2>/dev/null || true
echo "[cf-to-scp] Cleaned up"
