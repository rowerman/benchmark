#!/bin/bash
set -euo pipefail
K8S_ID="prv-09"
CLUSTER_NAME="cve-prv-09-helm"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
