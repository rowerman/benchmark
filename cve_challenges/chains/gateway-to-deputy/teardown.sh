#!/bin/bash
set -euo pipefail
echo "[gateway-to-deputy] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/lowcode-secrets/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/shared-nat/docker-compose.yml down -v 2>/dev/null || true
echo "[gateway-to-deputy] Cleaned up"
