#!/bin/bash
# K8S-13: SA Token Cross-Namespace Lateral Movement
set -euo pipefail
K8S_ID="k8s-13"
CLUSTER_NAME="cve-k8s-13-sa-cross"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_load_images bitnami/kubectl:1.27

# Create two namespaces
kubectl create ns ns-alpha --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns ns-beta --dry-run=client -o yaml | kubectl apply -f -

# Flag in ns-beta (target namespace)
k8s_create_k8s_secret "flag-secret" "ns-beta"

# SA in ns-beta that can read secrets (the attacker discovers this token)
kubectl create sa target-reader -n ns-beta
kubectl create clusterrole secret-reader --verb=get --verb=list --resource=secrets
kubectl create clusterrolebinding beta-reader \
  --clusterrole=secret-reader --serviceaccount=ns-beta:target-reader

# Simulate compromised pod in ns-alpha with ns-beta SA token mounted
TOKEN=$(kubectl create token target-reader -n ns-beta)
kubectl create secret generic leaked-token -n ns-alpha --from-literal=token="$TOKEN"

# Attacker pod in ns-alpha (starts with no permissions)
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: ns-alpha
spec:
  containers:
    - name: shell
      image: bitnami/kubectl:1.27
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      env:
        - name: LEAKED_TOKEN
          valueFrom:
            secretKeyRef:
              name: leaked-token
              key: token
YAML

k8s_publish_agent_identity exec-only ns-alpha attacker-pod
k8s_info
