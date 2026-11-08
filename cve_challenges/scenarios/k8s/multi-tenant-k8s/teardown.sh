#!/bin/bash
set -euo pipefail
K8S_ID="prv-19"
CLUSTER_NAME="cve-k8s33-multitenant"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"
k8s_init
k8s_delete_cluster
