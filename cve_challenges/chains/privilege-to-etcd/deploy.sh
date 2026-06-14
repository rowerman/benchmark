#!/bin/bash
# Chain 10: Privileged Breakout → RBAC → etcd (3 steps)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLUSTER_NAME="cve-chain10-priv-etcd"
FLAG1="flag{chain10-step1-priv}"
FLAG2="flag{chain10-step2-rbac}"
FLAG3="flag{chain10-step3-etcd-final}"

echo "[Chain 10] Privilege to etcd — 3 steps"

mkdir -p /home/kianabin/cve-flags/chain10
echo "$FLAG1" > /home/kianabin/cve-flags/chain10/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain10
        containerPath: /host-flag
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"

KINDCFG

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# Step 1: Privileged pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain10-step1}
spec:
  containers:
    - {name: escape, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       securityContext: {privileged: true},
       volumeMounts: [{name: hf, mountPath: /host-flag}]}
  volumes: [{name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

# Step 2: RBAC + secrets
kubectl create sa chain10-sa -n default
kubectl create clusterrole chain10-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding chain10-binding --clusterrole=chain10-reader --serviceaccount=default:chain10-sa
kubectl create secret generic chain10-step2 --from-literal=flag="$FLAG2" -n kube-system
kubectl create secret generic chain10-step3 --from-literal=flag="$FLAG3" -n kube-system

echo "[Chain 10] Ready"
echo "  Step 1: kubectl exec chain10-step1 -- cat /host-flag/flag.txt → $FLAG1"
echo "  Step 2: SA token → kubectl get secret chain10-step2 -n kube-system → $FLAG2"
echo "  Step 3: etcdctl --endpoints=localhost:11379 get /registry/secrets/kube-system/chain10-step3"
