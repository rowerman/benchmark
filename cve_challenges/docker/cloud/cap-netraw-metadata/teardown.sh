#!/bin/bash
set -euo pipefail
K8S_ID="cloud-02"
CLUSTER_NAME="cve-cloud02-cap-netraw"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
k8s_init
k8s_delete_cluster
