#!/bin/bash
set -euo pipefail
K8S_ID="k8s-19"
CLUSTER_NAME="cve-k8s-19-ptrace"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag
k8s_load_images ubuntu:22.04
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: ptrace-pod
spec:
  hostPID: true
  containers:
    - name: attacker
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
        runAsUser: 0
YAML

k8s_wait_pod "ptrace-pod"


k8s_publish_agent_identity exec-only default ptrace-pod
k8s_info
