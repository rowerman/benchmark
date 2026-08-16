#!/bin/bash
set -euo pipefail
echo "[Chain-42] tearing down..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/db/postgres-weak-auth/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/web/wordpress-simple-file-list/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-42] cleaned"
