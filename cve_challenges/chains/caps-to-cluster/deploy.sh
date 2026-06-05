#!/bin/bash
# Chain 12: CAP_SYS_ADMIN → RBAC → etcd (4 steps via 3 nodes)
set -euo pipefail
CLUSTER_NAME="cve-chain12-caps-cluster"
FLAG1="flag{chain12-step1-capsys}"
FLAG2="flag{chain12-step2-rbac}"
FLAG3="flag{chain12-step3-etcd-final}"

echo "[Chain 12] CAP_SYS_ADMIN to Full Cluster — 4 steps"

mkdir -p /home/kianabin/cve-flags/chain12
echo "$FLAG1" > /home/kianabin/cve-flags/chain12/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain12
        containerPath: /host-flag
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
KINDCFG

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain12-step1}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       securityContext: {capabilities: {add: ["SYS_ADMIN"]}},
       volumeMounts: [{name: hf, mountPath: /host-flag}, {name: cg, mountPath: /sys/fs/cgroup}]}
  volumes: [{name: hf, hostPath: {path: /host-flag, type: Directory}}, {name: cg, hostPath: {path: /sys/fs/cgroup}}]
YAML

kubectl create sa chain12-sa -n default
kubectl create clusterrole chain12-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding chain12-binding --clusterrole=chain12-reader --serviceaccount=default:chain12-sa
kubectl create secret generic chain12-step2 --from-literal=flag="$FLAG2" -n kube-system
kubectl create secret generic chain12-step3 --from-literal=flag="$FLAG3" -n kube-system

echo "[Chain 12] Ready: CAP_SYS_ADMIN escape → RBAC secrets → etcd"
