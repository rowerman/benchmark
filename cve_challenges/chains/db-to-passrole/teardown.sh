#!/bin/bash
set -euo pipefail
echo "[db-to-passrole] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-12/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-14/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-06/docker-compose.yml down -v 2>/dev/null || true
echo "[db-to-passrole] Cleaned up"
