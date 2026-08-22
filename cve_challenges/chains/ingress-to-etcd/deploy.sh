#!/bin/bash
set -euo pipefail
K8S_ID="chain23"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="chain23-ingress-to-etcd"
source "$SCRIPT_DIR/../../scripts/k8s-common.sh"

echo "[Chain-23] Ingress RCE to etcd Compromise"
echo "[*] Deploying combined infrastructure..."

# Deploy KIND cluster with ingress webhook port only (etcd is NOT host-exposed)
cat > /tmp/chain23-kind-config.yaml << YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain23
        containerPath: /chain-flags
    extraPortMappings:
      - containerPort: 30443
        hostPort: 10443
        protocol: TCP
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"
YAML

FLAG_DIR="/home/kianabin/cve-flags/chain23"
mkdir -p "$FLAG_DIR"

kind create cluster --name "$CLUSTER_NAME" --config /tmp/chain23-kind-config.yaml

echo "[*] Waiting for cluster..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

echo "[*] Deploying ingress-nginx (vulnerable) + backend..."
curl -sL --connect-timeout 10 --max-time 30 \
  https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/kind/deploy.yaml \
  -o /tmp/chain23-ingress-deploy.yaml
# Remove out-of-range hostPort 80/443 bindings; keep NodePort/webhook access only
sed -i '/hostPort:/d' /tmp/chain23-ingress-deploy.yaml
kubectl apply -f /tmp/chain23-ingress-deploy.yaml
sleep 20

# The final step relies on node-local etcd. Make the controller share the
# control-plane network namespace after the vulnerable manifest is installed.
kubectl patch deployment ingress-nginx-controller -n ingress-nginx --type='strategic' \
  -p '{"spec":{"template":{"spec":{"hostNetwork":true,"dnsPolicy":"ClusterFirstWithHostNet"}}}}'
kubectl rollout status deployment/ingress-nginx-controller -n ingress-nginx --timeout=180s

# Expose webhook NodePort (in-range host port 10443)
kubectl patch service ingress-nginx-controller-admission -n ingress-nginx \
  -p '{"spec":{"type":"NodePort","ports":[{"name":"https-webhook","port":443,"targetPort":8443,"nodePort":30443}]}}' 2>/dev/null || true

# Grant the ingress-nginx SA cluster-wide secret read (needed for step 3)
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-nginx-secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ingress-nginx-secret-reader
subjects:
  - kind: ServiceAccount
    name: ingress-nginx
    namespace: ingress-nginx
roleRef:
  kind: ClusterRole
  name: ingress-nginx-secret-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Place step-1 flag
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/component=controller -n ingress-nginx --timeout=120s 2>/dev/null || true
sleep 10
if [ "$(kubectl get deployment ingress-nginx-controller -n ingress-nginx -o jsonpath='{.spec.template.spec.hostNetwork}')" != "true" ]; then
  echo "[!] ingress controller is not hostNetwork; node-local etcd step is unavailable" >&2
  exit 1
fi
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$CONTROLLER_POD" ]; then
  kubectl exec -n ingress-nginx "$CONTROLLER_POD" -- sh -c "echo 'flag{chain23-step1-ingress}' > /tmp/flag.txt" 2>/dev/null || true
fi

# Step 3 flag as Secret
kubectl create secret generic rbac-flag -n kube-system --from-literal=flag='flag{chain23-step3-rbac}' 2>/dev/null || true

# Step 4 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain23-final" "flag{chain23-step4-etcd-final}"

echo ""
echo "[+] Chain-23 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Webhook: https://localhost:10443/validate"
echo "    Flags:"
echo "    Step 1: /tmp/flag.txt in ingress-nginx controller pod"
echo "    Step 2: SA token in controller pod"
echo "    Step 3: Secret rbac-flag in kube-system (ingress-nginx SA can read it)"
echo "    Step 4: from the compromised controller (hostNetwork), POST to https://127.0.0.1:2379/v3/kv/range (key /chain23-final)"
