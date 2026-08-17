#!/bin/bash
set -euo pipefail
K8S_ID="k8s-15"
CLUSTER_NAME="cve-k8s-15-image-tag"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
docker compose -f "$SCRIPT_DIR/registry-compose.yml" down -v 2>/dev/null || true
k8s_delete_cluster
