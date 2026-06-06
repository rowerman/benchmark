#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-33] Teardown — stopping components..."

docker compose -f "$ROOT/docker/web/ssti-jinja2/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/cloud/iam-privesc/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/cloud/sts-assumerole/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/cloud/kms-oracle/docker-compose.yml" down -v 2>/dev/null || true

echo "[Chain-33] Teardown complete"
