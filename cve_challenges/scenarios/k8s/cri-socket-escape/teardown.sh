#!/bin/bash
set -euo pipefail
K8S_ID="prv-44"
CLUSTER_NAME="cve-prv-44-cri-socket"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
