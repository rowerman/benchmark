#!/bin/bash
set -euo pipefail
echo "[Chain-43] tearing down..."
cd "$(dirname "$0")"
docker compose -f ../../scenarios/cloud/global-s3-squatting/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/beta-endpoint/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../../scenarios/cloud/iam-enum-oracle/docker-compose.yml down -v 2>/dev/null || true
echo "[Chain-43] cleaned"
