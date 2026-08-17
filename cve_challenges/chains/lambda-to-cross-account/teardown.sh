#!/bin/bash
set -euo pipefail
echo "[lambda-to-cross-account] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/iam-enum-oracle/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/lambda-passrole/docker-compose.yml down -v 2>/dev/null || true
echo "[lambda-to-cross-account] Cleaned up"
