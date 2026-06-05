#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLUSTER_NAME="cve-chain31-db-cluster"

FLAG1="flag{c31-step1-mysql}"
FLAG2="flag{c31-step2-docker}"
FLAG3="flag{c31-step3-rbac}"
FLAG4="flag{c31-step4-etcd}"

echo "[Chain-31] Database to K8s Cluster Admin — 4 steps, DB→Linux→K8s"

# Step 1: MySQL weak auth (Docker)
echo "=== Step 1: DB-02 MySQL Weak Auth ==="
docker compose -f "$ROOT/docker/db/mysql-udf-direct/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] MySQL at localhost:10202 (root:root)"

# Step 2: Docker socket abuse (Docker)
echo "=== Step 2: LNX-08 Docker Socket Abuse ==="
docker compose -f "$ROOT/docker/linux/docker-socket/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSH: ssh attacker@localhost -p 10303 (password: password123)"

# Steps 3-4: K8s cluster
echo "=== Steps 3-4: K8s RBAC → etcd ==="

mkdir -p /home/kianabin/cve-flags/chain31

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
KINDCFG

echo "  [*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# RBAC setup (K8S-06): SA with secrets list/get
kubectl create serviceaccount chain31-sa -n default
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain31-secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain31-attacker-binding
subjects:
  - kind: ServiceAccount
    name: chain31-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: chain31-secrets-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: chain31-pod
  namespace: default
spec:
  serviceAccountName: chain31-sa
  containers:
    - name: shell
      image: nginx:1.24-alpine
      command: ["sleep", "3600"]
YAML

# Stage 4 flag: etcd
kubectl create secret generic chain31-etcd-final \
  --from-literal=flag="$FLAG4" \
  -n kube-system

echo ""
echo "[Chain-31] Ready"
echo "  Step 1: MySQL root@localhost:10202 → UDF → flag{c31-step1-mysql}"
echo "  Step 2: SSH attacker@localhost -p 10303 → Docker socket → flag{c31-step2-docker}"
echo "  Step 3: kubectl exec chain31-pod -- ... → RBAC secrets → flag{c31-step3-rbac}"
echo "  Step 4: etcdctl --endpoints=localhost:11379 get /registry/... → flag{c31-step4-etcd}"
