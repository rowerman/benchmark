#!/bin/bash
set -euo pipefail
echo "[managed-db-lateral] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/extrareplica-repl/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/rds-logfdw/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
echo "[managed-db-lateral] Cleaned up"
