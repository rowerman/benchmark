#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-chain-cri-etcd"

echo "[Chain CRI-to-etcd] 3-step K8s attack chain"
echo "  K8S-16 (CRI Socket) -> K8S-11 (Privileged) -> K8S-08 (etcd)"

# Prepare flags
FLAG_DIR="/home/kianabin/cve-flags/chain21"
mkdir -p "$FLAG_DIR"
FLAG1="${CVE_FLAG_1:-flag{chain21-step1-cri}}"
FLAG2="${CVE_FLAG_2:-flag{chain21-step2-privileged}}"
FLAG3="${CVE_FLAG_3:-flag{chain21-step3-etcd}}"
echo "$FLAG1" > "$FLAG_DIR/step1.txt"
echo "$FLAG2" > "$FLAG_DIR/step2.txt"
echo "  Step 1: $FLAG1"
echo "  Step 2: $FLAG2"
echo "  Step 3: $FLAG3"

echo "[*] Creating unified KIND cluster..."
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
      - hostPath: /home/kianabin/cve-flags/chain21
        containerPath: /host-flag
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"

KINDCFG

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Stage 2: Flag secret in kube-system
kubectl create secret generic chain21-stage2 \
  --from-literal=flag="$FLAG2" \
  -n kube-system 2>/dev/null || true

# Stage 3: Flag in etcd
kubectl create secret generic chain21-final \
  --from-literal=flag="$FLAG3" \
  -n kube-system 2>/dev/null || true

# Build CRI escape pod image with ctr
docker build -t chain21-cri-pod:local -f - "$SCRIPT_DIR" << 'DOCKERFILE' 2>/dev/null || \
  echo "  Using alpine as fallback (install ctr manually in pod)"
FROM alpine:latest
RUN apk add --no-cache curl && \
    curl -sSL https://github.com/containerd/containerd/releases/download/v1.7.13/containerd-1.7.13-linux-amd64.tar.gz | \
    tar xz -C /usr/local bin/ctr
DOCKERFILE

kind load docker-image chain21-cri-pod:local --name "$CLUSTER_NAME" 2>/dev/null || true

# Deploy CRI-accessible pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain21-pod
  namespace: default
spec:
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: true
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[*] Waiting for pod readiness..."
kubectl wait --for=condition=Ready pod/chain21-pod --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain CRI-to-etcd] Ready"
echo "  Step 1: kubectl exec chain21-pod -- sh"
echo "    -> Install ctr: apk add curl && curl -sSL <containerd-url> | tar xz -C /usr/local"
echo "    -> Escape: ctr --address /run/containerd/containerd.sock run --rm --privileged"
echo "  Step 2: Read Kubernetes secrets from /etc/kubernetes on host"
echo "  Step 3: etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/chain21-final"
