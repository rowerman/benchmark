#!/bin/bash
set -euo pipefail
echo "[middleware-network] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/synlapse-ir/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/shared-nat/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/omigod-agent/docker-compose.yml down -v 2>/dev/null || true
echo "[middleware-network] Cleaned up"
