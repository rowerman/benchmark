#!/bin/bash
set -euo pipefail
echo "[ci-to-oidc] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-16/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-12/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-11/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-08/docker-compose.yml down -v 2>/dev/null || true
echo "[ci-to-oidc] Cleaned up"
