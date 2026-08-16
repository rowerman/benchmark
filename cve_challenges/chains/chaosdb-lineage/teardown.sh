#!/bin/bash
set -euo pipefail
echo "[chaosdb-lineage] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/attachme-volume/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/wireserver-bootstrap/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cosmiss-notebook/docker-compose.yml down -v 2>/dev/null || true
echo "[chaosdb-lineage] Cleaned up"
