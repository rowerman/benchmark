#!/bin/bash
# Chain 13: SA Cross-NS → RBAC → runC Escape (4 steps)
set -euo pipefail
CLUSTER_NAME="cve-chain13-sa-escape"
FLAG1="flag{chain13-step1-crossns}"
FLAG2="flag{chain13-step2-rbac}"
FLAG3="flag{chain13-step3-runc-final}"

echo "[Chain 13] SA Token Lateral to Escape — 4 steps"

mkdir -p /home/kianabin/cve-flags/chain13
echo "$FLAG3" > /home/kianabin/cve-flags/chain13/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain13
        containerPath: /host-flag
KINDCFG

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# Create namespaces
kubectl create ns ns-alpha --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns ns-beta --dry-run=client -o yaml | kubectl apply -f -

# Step 1: SA token cross-ns lateral
kubectl create sa beta-reader -n ns-beta
kubectl create clusterrole chain13-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding chain13-crb --clusterrole=chain13-reader --serviceaccount=ns-beta:beta-reader
TOKEN=$(kubectl create token beta-reader -n ns-beta --duration=2h)
kubectl create secret generic chain13-leaked-token -n ns-alpha --from-literal=flag="$FLAG1" --from-literal=token="$TOKEN"

# Step 2: RBAC secret in ns-beta
kubectl create secret generic chain13-step2-rbac -n ns-beta --from-literal=flag="$FLAG2"

# Step 3: RunC escape pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain13-final, namespace: ns-beta}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       volumeMounts: [{name: hf, mountPath: /host-flag}]}
  volumes: [{name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

echo "[Chain 13] Ready: cross-ns token → RBAC secrets → runC escape → host flag"
