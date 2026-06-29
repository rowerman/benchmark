#!/bin/bash
set -euo pipefail
K8S_ID="cloud-02"
CLUSTER_NAME="cve-cloud02-cap-netraw"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[CLOUD-02] Container Escape via CAP_NET_RAW → Metadata MITM"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_create_host_flag

# Deploy metadata server (simulated IMDS in cluster)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: metadata-server
  labels:
    app: metadata
spec:
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
                      creds = {"Code":"Success","AccessKeyId":"AKIACLOUD02EXAMPLE","SecretAccessKey":"cloud02-imds-secret","Token":"cloud02-session","Expiration":"2026-12-31T00:00:00Z"}
                      self.wfile.write(json.dumps(creds).encode())
                  else:
                      self.send_response(200); self.end_headers()
                      self.wfile.write(b"metadata\n")
          HTTPServer(('0.0.0.0',5000),M).serve_forever()
YAML

# Deploy victim pod
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: victim
  labels:
    app: victim
spec:
  containers:
    - name: app
      image: python:3.11-slim
      command: ["python3", "-c"]
      args:
        - |
          from http.server import HTTPServer, BaseHTTPRequestHandler
          import os
          flag = os.environ.get('FLAG','flag{cloud-02-step1-netraw}')
          class H(BaseHTTPRequestHandler):
              def do_GET(self):
                  self.send_response(200); self.end_headers()
                  self.wfile.write(flag.encode())
          HTTPServer(('0.0.0.0',8080),H).serve_forever()
      env:
        - name: FLAG
          value: "flag{cloud-02-step1-netraw}"
YAML

# Deploy attacker pod with CAP_NET_RAW + network tools
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  labels:
    app: attacker
spec:
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

echo "[+] CLOUD-02 Ready"
echo "    Attacker pod: kubectl exec -it attacker -- sh"
echo "    Victim pod: kubectl exec -it victim -- sh"
echo "    Metadata server: kubectl exec -it metadata-server -- sh"
echo "    Exploit: Use CAP_NET_RAW for ARP spoofing to MITM victim→metadata traffic"
