#!/bin/bash
set -euo pipefail
K8S_ID="k8s-07"
CLUSTER_NAME="cve-k8s-07-kubelet"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Flag in kube-system as a secret
k8s_create_k8s_secret "kubelet-flag" "kube-system"

# Deploy a pod with flag mounted as env var (visible via kubelet /pods API)
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: flag-holder
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
      env:
        - name: FLAG
          valueFrom:
            secretKeyRef:
              name: kubelet-flag
              key: flag
YAML

k8s_info
echo "[+] Kubelet runs on node:10250 with anonymous access"
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "[+] Attack: curl -k https://${NODE_IP}:10250/runningpods/"
