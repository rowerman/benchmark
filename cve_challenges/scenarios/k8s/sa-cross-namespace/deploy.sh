#!/bin/bash
set -euo pipefail
K8S_ID="k8s-32"
CLUSTER_NAME="cve-k8s32-sa-cross-ns"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-32] K8s SA Token → Cross-Namespace Access"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_create_host_flag

# Create namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Create overly permissive ServiceAccount in tenant-a
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: broad-sa
  namespace: tenant-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: broad-role
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/exec", "secrets"]
    verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: broad-binding
subjects:
  - kind: ServiceAccount
    name: broad-sa
    namespace: tenant-a
roleRef:
  kind: ClusterRole
  name: broad-role
  apiGroup: rbac.authorization.k8s.io
YAML

# Deploy attacker pod in tenant-a with broad SA
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: tenant-a
spec:
  serviceAccountName: broad-sa
  containers:
    - name: attacker
      image: python:3.11-slim
      command: ["sleep", "infinity"]
      env:
        - name: STEP1_FLAG
          value: "flag{k8s-32-step1-sa}"
YAML

# Deploy target pod in tenant-b with flag secret
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: target-flag
  namespace: tenant-b
stringData:
  flag: "flag{k8s-32-step2-cross-ns}"
---
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
          value: "flag{k8s-32-step2-cross-ns}"
YAML

echo "[+] K8S-32 Ready"
echo "    Attacker pod (tenant-a): kubectl exec -it -n tenant-a attacker -- sh"
echo "    Target flag: kubectl get secret -n tenant-b target-flag -o jsonpath='{.data.flag}' | base64 -d"
echo "    Exploit: Use broad SA token to access tenant-b resources"
