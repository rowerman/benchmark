#!/bin/bash
# Chain 11: hostPath → Kubelet → Registry → gitRepo (4 steps)
set -euo pipefail
CLUSTER_NAME="cve-chain11-hostpath-ds"
FLAG1="flag{chain11-step1-hostpath}"
FLAG2="flag{chain11-step2-kubelet}"
FLAG3="flag{chain11-step3-registry}"
FLAG4="flag{chain11-step4-gitrepo-final}"

echo "[Chain 11] hostPath to DaemonSet — 4 steps"

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

docker pull alpine:latest 2>/dev/null; kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true; sleep 10

# Step 1: hostPath pod
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata: {name: chain11-step1}
spec:
  containers:
    - {name: esc, image: alpine:latest, imagePullPolicy: IfNotPresent, command: ["sleep","3600"],
       volumeMounts: [{name: hl, mountPath: /host-log}, {name: hf, mountPath: /host-flag}]}
  volumes: [{name: hl, hostPath: {path: /var/log}}, {name: hf, hostPath: {path: /host-flag, type: Directory}}]
YAML

kubectl create secret generic chain11-kubelet --from-literal=flag="$FLAG2" -n kube-system
kubectl create secret generic chain11-registry --from-literal=flag="$FLAG3" -n kube-system
kubectl create secret generic chain11-final --from-literal=flag="$FLAG4" -n kube-system

echo "[Chain 11] Ready — 4 steps: hostPath → kubelet → registry → gitRepo"
