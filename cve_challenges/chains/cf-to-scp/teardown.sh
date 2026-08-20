#!/bin/bash
set -euo pipefail
echo "[cf-to-scp] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/scp-bypass/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/global-s3-squatting/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/cf-injection/docker-compose.yml down -v 2>/dev/null || true
echo "[cf-to-scp] Cleaned up"
