#!/bin/bash
set -euo pipefail
K8S_ID="prv-27"
CLUSTER_NAME="cve-k8s31-cap-netraw"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"
k8s_init
k8s_delete_cluster
