#!/bin/bash
# Chain 16: Redis unauth → privileged breakout → RBAC → etcd (4 steps)
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain16-redis-k8s"
FLAG1="flag{chain16-step1-redis}"
FLAG2="flag{chain16-step2-priv}"
FLAG3="flag{chain16-step3-rbac}"
FLAG4="flag{chain16-step4-etcd-final}"

echo "[Chain 16] Redis to K8s Cluster Admin — 4 steps"

# Step 1: Redis (Docker)
echo "[*] Starting DB-05 Redis..."
docker compose -f "$ROOT/docker/db/redis-unauth/docker-compose.yml" up -d --build 2>&1 | tail -2

# Steps 2-4: Unified K8s cluster
mkdir -p /home/kianabin/cve-flags/chain16
echo "$FLAG2" > /home/kianabin/cve-flags/chain16/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain16
        containerPath: /host-flag
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
KINDCFG

docker pull alpine:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# Privileged pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain16-step2}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       securityContext: {privileged: true},
       volumeMounts: [{name: hf, mountPath: /host-flag}]}
  volumes: [{name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

# RBAC secrets
kubectl create sa chain16-sa -n default
kubectl create clusterrole chain16-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding chain16-binding --clusterrole=chain16-reader --serviceaccount=default:chain16-sa
kubectl create secret generic chain16-step3 --from-literal=flag="$FLAG3" -n kube-system
kubectl create secret generic chain16-step4 --from-literal=flag="$FLAG4" -n kube-system

echo "[Chain 16] Ready"
echo "  Step 1: redis-cli -h localhost -p 10205 PING → $FLAG1"
echo "  Step 2: kubectl exec chain16-step2 -- cat /host-flag/flag.txt → $FLAG2"
echo "  Step 3: SA token → kubectl get secret chain16-step3 -n kube-system → $FLAG3"
echo "  Step 4: etcdctl → get /registry/secrets/kube-system/chain16-step4 → $FLAG4"
