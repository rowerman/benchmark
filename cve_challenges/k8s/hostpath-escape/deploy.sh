#!/bin/bash
# K8S-12: hostPath Writable Mount Escape
set -euo pipefail
K8S_ID="k8s-12"
CLUSTER_NAME="cve-k8s-12-hostpath"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_load_images alpine:latest
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
    - name: escape
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      volumeMounts:
        - name: host-log
          mountPath: /host-log
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-log
      hostPath:
        path: /var/log
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

k8s_info
echo "[+] Attack: /host-log symlink → sensitive host file → read /host-flag/flag.txt"
