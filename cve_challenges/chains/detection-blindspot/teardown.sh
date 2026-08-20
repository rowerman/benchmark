#!/bin/bash
set -euo pipefail
echo "[detection-blindspot] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/persistence-as-a-service/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/beta-endpoint/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/iam-enum-oracle/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/resource-explorer/docker-compose.yml down -v 2>/dev/null || true
echo "[detection-blindspot] Cleaned up"
