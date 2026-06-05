#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLUSTER_NAME="cve-chain-k8s-admin"

echo "[Chain 2] Container to Cluster Admin — 4 steps, K8s only"

# Pre-create flag dir (must exist before Docker bind-mount, or Docker creates it as root)
mkdir -p /home/kianabin/cve-flags/chain2-flags
echo "flag{chain2-step2-escape}" > /home/kianabin/cve-flags/chain2-flags/flag.txt

echo "[*] Creating unified KIND cluster with RBAC + runC escape + etcd exposure..."
# Single KIND cluster with all vulnerabilities configured
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain2-flags
        containerPath: /chain-flags
KINDCFG

# Wait for stability
echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Stage 1 flag: RBAC secret
kubectl create secret generic chain2-stage1 \
  --from-literal=flag="flag{chain2-step1-rbac}" \
  -n kube-system

# RBAC setup (K8S-06)
kubectl create serviceaccount attacker-sa -n default
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain2-secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain2-attacker-binding
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: chain2-secrets-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: chain2-pod
  namespace: default
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: shell
      image: nginx:1.24-alpine
      command: ["sleep", "3600"]
YAML

# Stage 3 flag: etcd
FLAG3="flag{chain2-step3-etcd-final}"
kubectl create secret generic chain2-etcd-final \
  --from-literal=flag="$FLAG3" \
  -n kube-system

echo ""
echo "[Chain 2] Ready"
echo "  Step 1: kubectl exec chain2-pod -- cat /run/secrets/kubernetes.io/serviceaccount/token → RBAC → flag{chain2-step1-rbac}"
echo "  Step 2: Escape container → cat /chain-flags/flag.txt → flag{chain2-step2-escape}"
echo "  Step 3: etcdctl --endpoints=localhost:11379 get /registry/secrets/kube-system/chain2-etcd-final → FINAL"
