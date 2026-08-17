#!/bin/bash
set -euo pipefail
K8S_ID="k8s-08"
CLUSTER_NAME="cve-k8s-08-etcd"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
docker rm -f cve-etcd-flag 2>/dev/null || true
