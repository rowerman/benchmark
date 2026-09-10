#!/bin/bash
# Chain 15: PostgreSQL SQLi → DB RCE → hostPath escape → Kubelet (4 steps)
set -euo pipefail
K8S_ID="chain15"
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain15-pg-node"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
FLAG1="${CVE_FLAG1:-flag{chain15-step1-sqli\}}"
FLAG2="${CVE_FLAG2:-flag{chain15-step2-db-rce\}}"
FLAG3="${CVE_FLAG3:-flag{chain15-step3-hostpath\}}"
FLAG4="${CVE_FLAG4:-flag{chain15-step4-kubelet-final\}}"

echo "[Chain 15] PostgreSQL SQLi to Node Compromise — 4 steps (all in one cluster)"

mkdir -p /home/kianabin/cve-flags/chain15
echo "$FLAG3" > /home/kianabin/cve-flags/chain15/flag.txt
# Writable host dir for the postgres hostPath escape (postgres user needs write)
mkdir -p /home/kianabin/cve-flags/chain15-write
chmod 777 /home/kianabin/cve-flags/chain15-write 2>/dev/null || true

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 30007
        hostPort: 10107
        protocol: TCP
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain15
        containerPath: /host-flag
      - hostPath: /home/kianabin/cve-flags/chain15-write
        containerPath: /host-write
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            anonymous-auth: "true"
            authorization-mode: "AlwaysAllow"
KINDCFG

docker pull python:3.11-slim 2>/dev/null || true
docker pull postgres:16.6 2>/dev/null || true
docker pull alpine:latest 2>/dev/null || true
kind load docker-image python:3.11-slim --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image postgres:16.6 --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# DB init: products table with step-1 flag
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: chain15-init
  namespace: default
data:
  init.sql: |
    CREATE TABLE IF NOT EXISTS products (name TEXT);
    INSERT INTO products (name) VALUES ('$FLAG1');
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: chain15-webapp
  namespace: default
data:
  app.py: |
    import os
    from flask import Flask, request
    import psycopg2
    app = Flask(__name__)
    def conn():
        return psycopg2.connect(host=os.environ['DB_HOST'], user=os.environ['DB_USER'],
                                password=os.environ['DB_PASS'], dbname=os.environ['DB_NAME'])
    @app.route('/')
    def index():
        return 'ok'
    @app.route('/search')
    def search():
        q = request.args.get('q', '')
        c = conn(); cur = c.cursor()
        cur.execute("SELECT name FROM products WHERE name LIKE '%" + q + "%'")
        rows = cur.fetchall()
        return '<br>'.join(r[0] for r in rows)
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=3000)
---
apiVersion: v1
kind: Service
metadata:
  name: chain15-pg
  namespace: default
spec:
  selector:
    app: chain15-pg
  ports:
    - port: 5432
      targetPort: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain15-pg
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain15-pg
  template:
    metadata:
      labels:
        app: chain15-pg
    spec:
      containers:
        - name: db
          image: postgres:16.6
          imagePullPolicy: IfNotPresent
          env:
            - name: POSTGRES_USER
              value: products
            - name: POSTGRES_PASSWORD
              value: postgres
            - name: POSTGRES_DB
              value: shop
          ports:
            - containerPort: 5432
          volumeMounts:
            - name: init
              mountPath: /docker-entrypoint-initdb.d
              readOnly: true
            - name: host-write
              mountPath: /host-write
      volumes:
        - name: init
          configMap:
            name: chain15-init
        - name: host-write
          hostPath:
            path: /host-write
            type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: chain15-web
  namespace: default
spec:
  selector:
    app: chain15-web
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 30007
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain15-web
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain15-web
  template:
    metadata:
      labels:
        app: chain15-web
    spec:
      containers:
        - name: web
          image: python:3.11-slim
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              pip install --no-cache-dir flask psycopg2-binary >/dev/null 2>&1
              exec python /app/app.py
          env:
            - name: DB_HOST
              value: chain15-pg
            - name: DB_USER
              value: products
            - name: DB_PASS
              value: postgres
            - name: DB_NAME
              value: shop
            - name: PGCLIENTENCODING
              value: BIG5
          ports:
            - containerPort: 3000
          volumeMounts:
            - name: app
              mountPath: /app
      volumes:
        - name: app
          configMap:
            name: chain15-webapp
YAML

# Step 2 flag: file inside the postgres pod (readable via COPY PROGRAM)
kubectl wait --for=condition=Ready pods -l app=chain15-pg --timeout=180s 2>/dev/null || true
kubectl wait --for=condition=Ready pods -l app=chain15-web --timeout=180s 2>/dev/null || true
PG_POD=$(kubectl get pods -l app=chain15-pg -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$PG_POD" -- sh -c "echo '$FLAG2' > /tmp/step2.txt" 2>/dev/null || true

# Step 4 final flag pod (kubelet anonymous exec target)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: chain15-final
  namespace: default
spec:
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - "echo '$FLAG4' > /flag.txt; sleep 3600"
YAML
kubectl wait --for=condition=Ready pod/chain15-final --timeout=60s 2>/dev/null || true
sleep 5

NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo ""
echo "[Chain 15] Ready"
echo "  Entry: http://localhost:10107/search?q= (PostgreSQL encoding-bypass SQLi)"
echo "  Step 1: SQLi -> read products row containing the flag"
echo "  Step 2: connect as superuser products/postgres -> COPY (SELECT 'x') TO PROGRAM 'cat /tmp/step2.txt'"
echo "  Step 3: COPY (SELECT 'x') TO PROGRAM 'ln -sf /host-flag /host-write/flag-link; cat /host-write/flag-link/flag.txt'"
echo "  Step 4: from the host use kubeletctl/websocket against https://${NODE_IP}:10250 -> exec into chain15-final -> cat /flag.txt"
