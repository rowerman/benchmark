#!/bin/bash
# Chain 14: Tomcat Deserialization to K8s Admin
# Scenarios: web-01 (Tomcat), lnx-05 (sudo chroot), k8s-06 (RBAC), k8s-08 (etcd)
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"

echo "[Chain 14] Tearing down..."

# Stop Docker scenarios
docker compose -f "$ROOT/docker/web/tomcat-deserialization/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/linux/sudo-chroot/docker-compose.yml" down -v 2>/dev/null || true

# Delete K8s clusters used by chain steps
kind delete cluster --name cve-k8s-06-rbac 2>/dev/null || true
kind delete cluster --name cve-k8s-08-etcd 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain14 2>/dev/null || true

echo "[Chain 14] Teardown complete"
