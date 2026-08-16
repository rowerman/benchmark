#!/bin/bash
set -euo pipefail
echo "[supply-chain-persistence] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/persistence-as-a-service/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/composer-depconf/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/buildfleet-registry/docker-compose.yml down -v 2>/dev/null || true
echo "[supply-chain-persistence] Cleaned up"
