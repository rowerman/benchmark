#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAIN_DIR="$SCRIPT_DIR"
CLUSTER_NAME="chain23-ingress-to-etcd"

echo "[Chain-23] Ingress RCE to etcd Compromise"
echo "[*] Deploying combined infrastructure..."

# Deploy KIND cluster with both ingress webhook port and etcd port
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
      - containerPort: 32379
        hostPort: 11379
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
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/kind/deploy.yaml
sleep 20

# Expose webhook
kubectl patch service ingress-nginx-controller-admission -n ingress-nginx \
  -p '{"spec":{"type":"NodePort","ports":[{"name":"https-webhook","port":443,"targetPort":8443,"nodePort":30443}]}}' 2>/dev/null || true

# Expose etcd
kubectl patch service kubernetes -n default \
  -p '{"spec":{"type":"NodePort","ports":[{"name":"etcd","port":2379,"targetPort":2379,"nodePort":32379}]}}' 2>/dev/null || true

# Place step-1 flag
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/component=controller -n ingress-nginx --timeout=120s 2>/dev/null || true
sleep 10
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$CONTROLLER_POD" ]; then
  kubectl exec -n ingress-nginx "$CONTROLLER_POD" -- sh -c "echo 'flag{chain23-step1-ingress}' > /tmp/flag.txt" 2>/dev/null || true
fi

# Place step-3 flag as Secret
kubectl create secret generic rbac-flag -n kube-system --from-literal=flag='flag{chain23-step3-rbac}' 2>/dev/null || true

# Place step-4 flag as Secret
kubectl create secret generic etcd-flag -n kube-system --from-literal=flag='flag{chain23-step4-etcd-final}' 2>/dev/null || true

echo ""
echo "[+] Chain-23 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Webhook: https://localhost:10443/validate"
echo "    etcd port: localhost:11379"
echo ""
echo "    Flags:"
echo "    Step 1: /tmp/flag.txt in ingress-nginx controller pod"
echo "    Step 2: SA token in controller pod"
echo "    Step 3: Secret rbac-flag in kube-system"
echo "    Step 4: Secret etcd-flag in kube-system"