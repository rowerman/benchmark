#!/bin/bash
set -euo pipefail
echo "[middleware-network] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/synlapse-ir/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/shared-nat/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/omigod-agent/docker-compose.yml down -v 2>/dev/null || true
echo "[middleware-network] Cleaned up"
