#!/bin/bash
set -euo pipefail
K8S_ID="prv-15"
CLUSTER_NAME="cve-prv-15-hostpath"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster
