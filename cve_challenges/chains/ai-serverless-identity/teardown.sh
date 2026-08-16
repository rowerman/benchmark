#!/bin/bash
set -euo pipefail
echo "[ai-serverless-identity] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/actor-token/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/serverless-sa/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/pickle-model/docker-compose.yml down -v 2>/dev/null || true
echo "[ai-serverless-identity] Cleaned up"
