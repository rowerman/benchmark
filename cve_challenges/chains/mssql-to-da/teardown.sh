#!/bin/bash
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
docker compose -f "$ROOT/docker/web/mssql-xp-cmdshell/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/db/mssql-linked-server/docker-compose.yml" down -v 2>/dev/null || true
echo "[Chain 9] Docker nodes cleaned."
