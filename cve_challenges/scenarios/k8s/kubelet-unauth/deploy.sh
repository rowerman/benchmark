#!/bin/bash
set -euo pipefail
K8S_ID="k8s-07"
CLUSTER_NAME="cve-k8s-07-kubelet"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_load_images nginx:1.24-alpine

# Flag 不进 env/args：匿名 kubelet 的 /pods 会把 pod spec 整份返回，
# 明文写进 env 就等于把 flag 挂在门口。只有经 kubelet 命令执行进容器才读得到。
k8s_apply << YAML
apiVersion: v1
kind: Pod
metadata:
  name: flag-holder
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "flag-holder"
printf '%s\n' "$FLAG" | kubectl exec -i flag-holder -- sh -c 'cat > /flag.txt && chmod 600 /flag.txt'

k8s_publish_agent_identity node-reader default
k8s_info
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
