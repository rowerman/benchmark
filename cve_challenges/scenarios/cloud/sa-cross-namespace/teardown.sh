#!/bin/bash
set -euo pipefail
K8S_ID="cloud-03"
CLUSTER_NAME="cve-cloud03-sa-cross-ns"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
k8s_init
k8s_delete_cluster
