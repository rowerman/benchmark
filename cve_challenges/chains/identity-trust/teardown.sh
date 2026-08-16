#!/bin/bash
set -euo pipefail
echo "[identity-trust] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../docker/cloud/lowcode-secrets/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/actor-token/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/golden-saml/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../docker/cloud/iam-enum-oracle/docker-compose.yml down -v 2>/dev/null || true
echo "[identity-trust] Cleaned up"
