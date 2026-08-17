#!/bin/bash
set -euo pipefail
echo "[ci-to-oidc] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/cross-account-trust/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/oidc-federation/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/ci-poisoning/docker-compose.yml down -v 2>/dev/null || true
echo "[ci-to-oidc] Cleaned up"
