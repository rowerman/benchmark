#!/bin/bash
set -euo pipefail
K8S_ID="prv-38"
CLUSTER_NAME="cve-prv-38-registry"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
docker rm -f k8s-registry 2>/dev/null || echo "  Registry container already removed"
