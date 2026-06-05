#!/bin/bash
# Chain 17: WordPress LFI → RCE → K8s RBAC → runC escape → etcd (4 steps)
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain17-wp-lfi"
FLAG1="flag{chain17-step1-lfi}"
FLAG2="flag{chain17-step2-rbac}"
FLAG3="flag{chain17-step3-runc}"
FLAG4="flag{chain17-step4-etcd-final}"

echo "[Chain 17] WordPress LFI to Cluster Admin"

# Step 1: WordPress Jupiter X Core
docker compose -f "$ROOT/docker/web/wordpress-jupiterx-lfi/docker-compose.yml" up -d --build 2>&1 | tail -2

# Steps 2-4: Unified K8s cluster
mkdir -p /home/kianabin/cve-flags/chain17
echo "$FLAG3" > /home/kianabin/cve-flags/chain17/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain17
        containerPath: /host-flag
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
KINDCFG

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# RBAC setup
kubectl create sa chain17-sa -n default
kubectl create clusterrole chain17-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding chain17-binding --clusterrole=chain17-reader --serviceaccount=default:chain17-sa
kubectl create secret generic chain17-step2 --from-literal=flag="$FLAG2" -n kube-system

# RunC escape pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain17-final}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       volumeMounts: [{name: hf, mountPath: /host-flag}]}
  volumes: [{name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

kubectl create secret generic chain17-step4 --from-literal=flag="$FLAG4" -n kube-system

echo "[Chain 17] Ready: WP LFI → RCE → RBAC → runC escape → etcd"
