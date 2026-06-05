#!/bin/bash
# Chain 15: PostgreSQL SQLi → DB RCE → hostPath escape → Kubelet (4 steps)
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain15-pg-node"
FLAG1="flag{chain15-step1-sqli}"
FLAG2="flag{chain15-step2-db-rce}"
FLAG3="flag{chain15-step3-hostpath}"
FLAG4="flag{chain15-step4-kubelet-final}"

echo "[Chain 15] PostgreSQL SQLi to Node Compromise"

# Step 1: PostgreSQL + web app
echo "[*] Starting WEB-07 + DB-01..."
docker compose -f "$ROOT/docker/web/postgres-sqli/docker-compose.yml" up -d --build 2>&1 | tail -2
docker compose -f "$ROOT/docker/db/postgres-weak-auth/docker-compose.yml" up -d 2>&1 | tail -2

# Step 2-4: K8s cluster
mkdir -p /home/kianabin/cve-flags/chain15
echo "$FLAG3" > /home/kianabin/cve-flags/chain15/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain15
        containerPath: /host-flag
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            anonymous-auth: "true"
            authorization-mode: "AlwaysAllow"
KINDCFG

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# hostPath pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain15-hostpath}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       volumeMounts: [{name: hl, mountPath: /host-log}, {name: hf, mountPath: /host-flag}]}
  volumes: [{name: hl, hostPath: {path: /var/log}}, {name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

kubectl create secret generic chain15-step4-final --from-literal=flag="$FLAG4" -n kube-system

echo "[Chain 15] Ready"
echo "  Step 1: curl WEB-07 /search?q=... SQLi → flag{chain15-step1-sqli}"
echo "  Step 2: psql DB-01 → COPY PROGRAM → RCE → flag{chain15-step2-db-rce}"
echo "  Step 3: hostPath symlink → cat /host-flag/flag.txt → $FLAG3"
echo "  Step 4: Kubelet API → get chain15-step4-final → $FLAG4"
