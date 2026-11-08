#!/bin/bash
set -euo pipefail
K8S_ID="prv-10"
CLUSTER_NAME="cve-prv-10-ingress-rce"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_delete_cluster