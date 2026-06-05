#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain25-seccomp-to-escape"
FLAG_DIR="/home/kianabin/cve-flags/chain25"
mkdir -p "$FLAG_DIR"

echo "[Chain-25] hostPID to CRI Socket Escape"
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

echo "flag{chain25-step1-seccomp}" > "$FLAG_DIR/flag.txt"

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
        runAsUser: 1000
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
YAML

kubectl wait --for=condition=Ready pod/locked-down-pod --timeout=60s 2>/dev/null || true
sleep 5

# Store final flag on the node (via Docker exec into the KIND node)
NODE_CONTAINER=$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null || echo "")
if [ -n "$NODE_CONTAINER" ]; then
  docker exec "$NODE_CONTAINER" sh -c "echo 'flag{chain25-step3-escape-final}' > /etc/chain25_final_flag" 2>/dev/null || true
fi

echo ""
echo "[+] Chain-25 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Step 1: /host-flag/flag.txt (via /proc/1/root)"
echo "    Step 2: CRI socket available at /run/containerd/containerd.sock"
echo "    Step 3: /etc/chain25_final_flag on node"