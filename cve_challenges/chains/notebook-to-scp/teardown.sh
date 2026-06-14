#!/bin/bash
set -euo pipefail
echo "[notebook-to-scp] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-16/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-17/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-09/docker-compose.yml down -v 2>/dev/null || true
echo "[notebook-to-scp] Cleaned up"
