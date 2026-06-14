#!/bin/bash
set -euo pipefail
echo "[ssrf-to-oidc] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/cloud-12/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-11/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/cloud-01/docker-compose.yml down -v 2>/dev/null || true
echo "[ssrf-to-oidc] Cleaned up"
