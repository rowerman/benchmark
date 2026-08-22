#!/bin/bash
set -euo pipefail
K8S_ID="cloud-02"
CLUSTER_NAME="cve-cloud02-cap-netraw"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[CLOUD-02] CAP_NET_RAW -> Metadata MITM"
k8s_init
k8s_create_cluster
k8s_wait_ready

NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
IMDS_FLAG="${CVE_FLAG:-flag{cloud-02-step1-netraw}}"

# The simulated IMDS is reachable through a Service and only from victim pods.
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: metadata-server
  labels:
    app: metadata
spec:
  nodeName: ${NODE_NAME}
  containers:
    - name: metadata
      image: python:3.11-slim
      command: ["python3", "-c"]
      args:
        - |
          from http.server import HTTPServer, BaseHTTPRequestHandler
          import json, os
          class M(BaseHTTPRequestHandler):
              def do_GET(self):
                  if 'security-credentials' in self.path:
                      self.send_response(200)
                      self.send_header('Content-Type','application/json')
                      self.end_headers()
                      creds = {"Code":"Success","AccessKeyId":"AKIACLOUD02EXAMPLE","SecretAccessKey":"cloud02-imds-secret","Token":"cloud02-session","Expiration":"2026-12-31T00:00:00Z","Flag":os.environ["FLAG"]}
                      self.wfile.write(json.dumps(creds).encode())
                  else:
                      self.send_response(200); self.end_headers(); self.wfile.write(b"metadata\n")
          HTTPServer(('0.0.0.0',5000),M).serve_forever()
      env:
        - name: FLAG
          value: "${IMDS_FLAG}"
---
apiVersion: v1
kind: Service
metadata:
  name: metadata
spec:
  selector:
    app: metadata
  ports:
    - name: imds
      port: 5000
      targetPort: 5000
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-victim-only
spec:
  podSelector:
    matchLabels:
      app: metadata
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: victim
      ports:
        - protocol: TCP
          port: 5000
YAML

# The victim continuously requests the credentials endpoint. The flag is
# delivered only in that response, not mounted into the victim container.
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: victim
  labels:
    app: victim
spec:
  nodeName: ${NODE_NAME}
  containers:
    - name: app
      image: python:3.11-slim
      command: ["sh", "-c"]
      args:
        - |
          while true; do
            python3 -c 'import urllib.request; u="http://metadata.default.svc.cluster.local:5000/latest/meta-data/iam/security-credentials/"; r=urllib.request.urlopen(u, timeout=3); open("/tmp/metadata-credentials.json", "wb").write(r.read())' || true
            sleep 3
          done
YAML

# The attacker shares the node and has CAP_NET_RAW for packet observation and
# ARP manipulation. It has no flag or metadata volume mounted into the pod.
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  labels:
    app: attacker
spec:
  nodeName: ${NODE_NAME}
  containers:
    - name: attacker
      image: python:3.11-slim
      command: ["sh", "-c"]
      args:
        - "apt-get update -qq && apt-get install -y -qq dsniff tcpdump iproute2 2>/dev/null; echo 'Tools ready: arpspoof, tcpdump, ip'; sleep infinity"
      securityContext:
        capabilities:
          add: ["NET_RAW"]
YAML

kubectl wait --for=condition=Ready pod/metadata-server --timeout=120s
kubectl wait --for=condition=Ready pod/victim --timeout=120s
kubectl wait --for=condition=Ready pod/attacker --timeout=120s
echo "[+] CLOUD-02 Ready"
echo "    Attacker pod: kubectl exec -it attacker -- sh"
echo "    Metadata Service: metadata.default.svc.cluster.local:5000"
echo "    Victim cache: kubectl exec victim -- cat /tmp/metadata-credentials.json"
echo "    Exploit: use CAP_NET_RAW to observe/redirect victim -> metadata traffic"
