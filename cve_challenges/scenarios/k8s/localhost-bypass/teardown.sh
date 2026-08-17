#!/bin/bash
set -euo pipefail
K8S_ID="k8s-24"
CLUSTER_NAME="cve-k8s-24-localhost-bypass"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster