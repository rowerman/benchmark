#!/bin/bash
set -euo pipefail
echo "[Chain-42] tearing down..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/ssrf-to-imds/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/db/postgres-weak-auth/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/web/wordpress-simple-file-list/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-42] cleaned"
