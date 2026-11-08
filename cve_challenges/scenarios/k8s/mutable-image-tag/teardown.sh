#!/bin/bash
set -euo pipefail
K8S_ID="prv-39"
CLUSTER_NAME="cve-prv-39-image-tag"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
docker compose -f "$SCRIPT_DIR/registry-compose.yml" down -v 2>/dev/null || true
k8s_delete_cluster
