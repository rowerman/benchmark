#!/bin/bash
set -euo pipefail
K8S_ID="k8s-24"
CLUSTER_NAME="cve-k8s-24-localhost-bypass"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-24] CVE-2020-8558 kube-proxy Localhost Boundary Bypass"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag

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
        - "printf 'server { listen 127.0.0.1:11080; location = /flag { root /usr/share/nginx/html; try_files /flag.txt =404; } }' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
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
      env:
        # 落脚 pod 用 downward API 自报所在节点地址（不含任何秘密）
        - name: NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
YAML

echo "[*] Waiting for pods..."
k8s_wait_pod "localhost-service" "sensitive-ns"
k8s_wait_pod "attacker" "default"
# flag 只写进服务容器的静态文件（不进 pod spec）
printf '%s\n' "$FLAG" | kubectl exec -i -n sensitive-ns localhost-service -- sh -c 'cat > /usr/share/nginx/html/flag.txt'
sleep 5

# Get node IP for the attacker
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

# CVE-2020-8558 的前提在 kind 上被 kube-proxy 的缓解规则挡住，这里按"漏洞前提"还原：
#   1. 节点打开 route_localnet（kube-proxy 的默认行为，也是该 CVE 的根因）；
#   2. 平台侧有一条把节点地址:11080 NAT 到 127.0.0.1:11080 的规则（本机服务被误暴露给
#      Pod 网段；等价于 CVE 里"Pod 能到达节点 127.0.0.1 上的服务"的可复现形态）。
# 只动这个一次性 KIND 节点容器，不改宿主全局内核参数。
NODE_CTR="$(k8s_get_node_container)"
if [ -n "$NODE_CTR" ]; then
    docker exec "$NODE_CTR" sh -c 'for f in /proc/sys/net/ipv4/conf/*/route_localnet; do echo 1 > "$f" 2>/dev/null || true; done'
    docker exec "$NODE_CTR" iptables -t nat -C PREROUTING -p tcp -d "$NODE_IP" --dport 11080 \
        -j DNAT --to-destination 127.0.0.1:11080 2>/dev/null || \
        docker exec "$NODE_CTR" iptables -t nat -A PREROUTING -p tcp -d "$NODE_IP" --dport 11080 \
            -j DNAT --to-destination 127.0.0.1:11080
    echo "[K8S-24] node route_localnet=1；已把 ${NODE_IP}:11080 NAT 到 127.0.0.1:11080"
fi

k8s_publish_agent_identity exec-only default attacker
k8s_info
