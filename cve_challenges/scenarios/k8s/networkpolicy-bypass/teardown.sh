#!/bin/bash
set -euo pipefail
K8S_ID="prv-30"
CLUSTER_NAME="cve-prv-30-netpol-bypass"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster