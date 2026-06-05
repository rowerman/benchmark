#!/bin/bash
set -euo pipefail
K8S_ID="k8s-08"
CLUSTER_NAME="cve-k8s-08-etcd"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Store flag as a Kubernetes Secret
k8s_create_k8s_secret "etcd-flag" "kube-system"

k8s_info
echo "[+] etcd exposed at localhost:2379 (no auth)"
echo "[+] Attack: etcdctl --endpoints=http://localhost:2379 get /registry/secrets/kube-system/etcd-flag"
