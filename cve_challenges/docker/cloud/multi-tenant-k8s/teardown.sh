#!/bin/bash
set -euo pipefail
K8S_ID="cloud-19"
CLUSTER_NAME="cve-cloud19-multitenant"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
k8s_init
k8s_delete_cluster
