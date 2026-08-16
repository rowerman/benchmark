#!/bin/bash
set -euo pipefail
echo "[managed-data-lateral] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/dataform-pt/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/synlapse-ir/docker-compose.yml down -v 2>/dev/null || true
echo "[managed-data-lateral] Cleaned up"
