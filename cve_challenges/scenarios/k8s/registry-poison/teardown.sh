#!/bin/bash
set -euo pipefail
K8S_ID="k8s-09"
CLUSTER_NAME="cve-k8s-09-registry"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
docker rm -f k8s-registry 2>/dev/null || echo "  Registry container already removed"
