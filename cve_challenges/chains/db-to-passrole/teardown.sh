#!/bin/bash
set -euo pipefail
echo "[db-to-passrole] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/lambda-passrole/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloudsql-index-rce/docker-compose.yml down -v 2>/dev/null || true
echo "[db-to-passrole] Cleaned up"
