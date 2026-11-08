# Scenario ID Migration

This benchmark separates scenario semantics by directory and keeps the
historical evaluation IDs traceable through two renumbering steps.

- `scenarios/cloud/` contains public-cloud scenarios only.
- `scenarios/k8s/` contains all private-cloud scenarios, regardless of delivery type.
- The private-cloud identifiers are now grouped into the paper's main set
  `k8s-01..k8s-40` and reserve set `k8s-41..k8s-60`.
- Scenario directories remain semantic; only stable IDs and persisted ID
  references changed.

Flags use the final scenario ID as their prefix. Dependencies that persist
scenario IDs should use the final mapping below.

## Public cloud renumbering

| Old ID | New ID | Scenario | Path |
|---|---|---|---|
| `cloud-11` | `cloud-01` | Global S3 Namespace Squatting | `scenarios/cloud/global-s3-squatting` |
| `cloud-26` | `cloud-02` | Dependency Confusion in Managed Data Platform | `scenarios/cloud/composer-depconf` |

## Private cloud migration from the original evaluation IDs

The 29 scenarios migrated from the former `cloud-*` namespace now use the
following final private-cloud IDs.

| Old ID | New ID | Scenario | Old path | New path |
|---|---|---|---|---|
| `cloud-01` | `k8s-41` | SSRF to Instance Metadata Credential Theft | `scenarios/cloud/ssrf-to-imds` | `scenarios/k8s/ssrf-to-imds` |
| `cloud-02` | `k8s-23` | CAP_NET_RAW to Metadata MITM | `scenarios/cloud/cap-netraw-metadata` | `scenarios/k8s/cap-netraw-metadata` |
| `cloud-03` | `k8s-47` | Serverless Code Injection to IAM PassRole | `scenarios/cloud/lambda-passrole` | `scenarios/k8s/lambda-passrole` |
| `cloud-04` | `k8s-13` | Private IaC Template Injection | `scenarios/cloud/cf-injection` | `scenarios/k8s/cf-injection` |
| `cloud-05` | `k8s-48` | Private CI/CD Pipeline Poisoning | `scenarios/cloud/ci-poisoning` | `scenarios/k8s/ci-poisoning` |
| `cloud-06` | `k8s-25` | Managed Notebook Escape | `scenarios/cloud/notebook-escape` | `scenarios/k8s/notebook-escape` |
| `cloud-07` | `k8s-49` | OIDC Claim Mismatch | `scenarios/cloud/oidc-federation` | `scenarios/k8s/oidc-federation` |
| `cloud-08` | `k8s-05` | IAM Cross-Project Trust Policy Takeover | `scenarios/cloud/cross-account-trust` | `scenarios/k8s/cross-account-trust` |
| `cloud-09` | `k8s-06` | Golden SAML Trust-Root Compromise | `scenarios/cloud/golden-saml` | `scenarios/k8s/golden-saml` |
| `cloud-10` | `k8s-07` | Tenant Policy Bypass via Legacy API | `scenarios/cloud/scp-bypass` | `scenarios/k8s/scp-bypass` |
| `cloud-12` | `k8s-50` | Managed Notebook Front-End Cross-Tenant RCE | `scenarios/cloud/cosmiss-notebook` | `scenarios/k8s/cosmiss-notebook` |
| `cloud-13` | `k8s-33` | Managed PostgreSQL FDW Host File Read | `scenarios/cloud/rds-logfdw` | `scenarios/k8s/rds-logfdw` |
| `cloud-14` | `k8s-34` | Managed PostgreSQL Engine Patch Host RCE | `scenarios/cloud/cloudsql-index-rce` | `scenarios/k8s/cloudsql-index-rce` |
| `cloud-15` | `k8s-35` | Shared Integration Runtime Credentials | `scenarios/cloud/synlapse-ir` | `scenarios/k8s/synlapse-ir` |
| `cloud-16` | `k8s-51` | Managed DB Internal Subnet and CN Bypass | `scenarios/cloud/extrareplica-repl` | `scenarios/k8s/extrareplica-repl` |
| `cloud-17` | `k8s-26` | K8s Host-Agent Bootstrap Secret Theft | `scenarios/cloud/wireserver-bootstrap` | `scenarios/k8s/wireserver-bootstrap` |
| `cloud-18` | `k8s-40` | Build Fleet and Private Registry Overwrite | `scenarios/cloud/buildfleet-registry` | `scenarios/k8s/buildfleet-registry` |
| `cloud-19` | `k8s-27` | Malicious Model Loading to Node Metadata | `scenarios/cloud/pickle-model` | `scenarios/k8s/pickle-model` |
| `cloud-20` | `k8s-52` | Predictable Volume ID Ownership Bypass | `scenarios/cloud/attachme-volume` | `scenarios/k8s/attachme-volume` |
| `cloud-21` | `k8s-53` | Directory Actor Token Identity Confusion | `scenarios/cloud/actor-token` | `scenarios/k8s/actor-token` |
| `cloud-22` | `k8s-54` | Platform Middleware Management Channel | `scenarios/cloud/omigod-agent` | `scenarios/k8s/omigod-agent` |
| `cloud-23` | `k8s-55` | IAM Enumeration AccessDenied Oracle | `scenarios/cloud/iam-enum-oracle` | `scenarios/k8s/iam-enum-oracle` |
| `cloud-24` | `k8s-56` | Private Service Catalog Invisible Write | `scenarios/cloud/beta-endpoint` | `scenarios/k8s/beta-endpoint` |
| `cloud-25` | `k8s-57` | Private Resource Explorer Enumeration | `scenarios/cloud/resource-explorer` | `scenarios/k8s/resource-explorer` |
| `cloud-27` | `k8s-36` | Low-Code Connector Secret Disclosure | `scenarios/cloud/lowcode-secrets` | `scenarios/k8s/lowcode-secrets` |
| `cloud-28` | `k8s-58` | Shared NAT Source-IP Allowlist Bypass | `scenarios/cloud/shared-nat` | `scenarios/k8s/shared-nat` |
| `cloud-29` | `k8s-59` | Managed Data Workflow Path Traversal | `scenarios/cloud/dataform-pt` | `scenarios/k8s/dataform-pt` |
| `cloud-30` | `k8s-60` | Serverless Default Service Account Escalation | `scenarios/cloud/serverless-sa` | `scenarios/k8s/serverless-sa` |
| `cloud-31` | `k8s-37` | Managed Automation Persistence | `scenarios/cloud/persistence-as-a-service` | `scenarios/k8s/persistence-as-a-service` |

## Final private-cloud renumbering

The left side is the private-cloud ID used immediately before the paper
selection; the right side is the final benchmark ID. The first 40 scenarios
form the paper evaluation set and are grouped by mechanism family. The last
20 are retained as reserve scenarios.

### Main set: `k8s-01..k8s-40`

```text
01←06, 02←25, 03←26, 04←32, 05←39, 06←40, 07←41,
08←07, 09←10, 10←20, 11←21, 12←24, 13←35,
14←01, 15←02, 16←03, 17←05, 18←11, 19←12, 20←14,
21←17, 22←23, 23←31, 24←33, 25←37, 26←47, 27←49,
28←22, 29←27, 30←28, 31←29, 32←30,
33←43, 34←44, 35←45, 36←56, 37←60,
38←09, 39←15, 40←48
```

The main set contains 26 original private-cloud scenarios and 14 migrated
private-cloud scenarios. The scenarios that used the pre-renumbering IDs
`k8s-08`, `k8s-13`, `k8s-16`, `k8s-18`, and `k8s-19` are now the reserve IDs
`k8s-42`, `k8s-43`, `k8s-44`, `k8s-45`, and `k8s-46`.

### Reserve set: `k8s-41..k8s-60`

```text
41←04, 42←08, 43←13, 44←16, 45←18, 46←19,
47←34, 48←36, 49←38, 50←42, 51←46, 52←50,
53←51, 54←52, 55←53, 56←54, 57←55, 58←57,
59←58, 60←59
```

## v3 Private-cloud renumbering

v3 replaces every private-cloud stable identifier with the `prv` namespace.
The history column preserves the complete lineage through the two earlier
migrations; frozen result IDs remain unchanged.

### Main set: `prv-01..prv-40`

| Historical ID chain | Current `k8s` ID | New `prv` ID | Scenario | Path | First-level boundary | Secondary mechanism | Frozen result ID |
|---|---|---|---|---|---|---|---|
| k8s-06 → k8s-01 → prv-01 | k8s-01 | prv-01 | K8s RBAC Secrets Abuse | `scenarios/k8s/rbac-secrets` | 控制面请求处理边界 | A1 Kubernetes RBAC 越权 | `k8s-06` |
| k8s-25 → k8s-02 → prv-04 | k8s-02 | prv-04 | MutatingWebhookConfiguration Overprivileged Registration | `scenarios/k8s/webhook-inject` | 控制面请求处理边界 | A2 准入链配置劫持 | `k8s-25` |
| k8s-26 → k8s-03 → prv-02 | k8s-03 | prv-02 | Node-Operator Overprivileged RBAC | `scenarios/k8s/node-redirect` | 控制面请求处理边界 | A1 Kubernetes RBAC 越权 | `k8s-26` |
| k8s-32 → k8s-04 → prv-03 | k8s-04 | prv-03 | K8s SA Token → Cross-Namespace Access | `scenarios/k8s/sa-cross-namespace` | 控制面请求处理边界 | A1 Kubernetes RBAC 越权 | `k8s-32` |
| cloud-08 → k8s-39 → k8s-05 → prv-05 | k8s-05 | prv-05 | IAM Trust Policy Principal:* → Cross-Project Takeover | `scenarios/k8s/cross-account-trust` | 控制面请求处理边界 | A3 云身份信任策略滥用 | `cloud-08` |
| cloud-09 → k8s-40 → k8s-06 → prv-06 | k8s-06 | prv-06 | Golden SAML → Internal Federation Trust Root Compromise | `scenarios/k8s/golden-saml` | 控制面请求处理边界 | A4 联邦身份断言伪造 | `cloud-09` |
| cloud-10 → k8s-41 → k8s-07 → prv-07 | k8s-07 | prv-07 | Tenant Policy Bypass via Legacy API Version | `scenarios/k8s/scp-bypass` | 控制面请求处理边界 | A5 控制面策略执行路径不一致 | `cloud-10` |
| k8s-07 → k8s-08 → prv-08 | k8s-08 | prv-08 | Kubelet API Anonymous Access | `scenarios/k8s/kubelet-unauth` | 控制面请求处理边界 | A6 控制面服务认证缺失 | `k8s-07` |
| k8s-10 → k8s-09 → prv-09 | k8s-09 | prv-09 | Helm v2 Tiller Unauthenticated | `scenarios/k8s/helm-tiller` | 控制面请求处理边界 | A6 控制面服务认证缺失 | `k8s-10` |
| k8s-20 → k8s-10 → prv-10 | k8s-10 | prv-10 | ingress-nginx Admission Controller RCE (IngressNightmare) | `scenarios/k8s/ingress-nginx-rce` | 控制面请求处理边界 | A7 控制面输入注入 | `k8s-20` |
| k8s-21 → k8s-11 → prv-11 | k8s-11 | prv-11 | ingress-nginx Lua Snippet Secret Extraction | `scenarios/k8s/ingress-snippet` | 控制面请求处理边界 | A7 控制面输入注入 | `k8s-21` |
| k8s-24 → k8s-12 → prv-26 | k8s-12 | prv-26 | kube-proxy Localhost Boundary Bypass | `scenarios/k8s/localhost-bypass` | 工作负载可达与放置边界 | C1 网络路径与地址操纵 | `k8s-24` |
| cloud-04 → k8s-35 → k8s-13 → prv-12 | k8s-13 | prv-12 | Private IaC Template Injection → Internal Secret Store | `scenarios/k8s/cf-injection` | 控制面请求处理边界 | A7 控制面输入注入 | `cloud-04` |
| k8s-01 → k8s-14 → prv-13 | k8s-14 | prv-13 | runC WORKDIR Container Escape | `scenarios/k8s/runc-cve-2024-21626` | 工作负载—节点运行时边界 | B1 容器运行时实现漏洞 | `k8s-01` |
| k8s-02 → k8s-15 → prv-14 | k8s-15 | prv-14 | K8s Cross-Pod Log Symlink Escape | `scenarios/k8s/runc-cve-2025-31133` | 工作负载—节点运行时边界 | B2 宿主路径与符号链接越界 | `k8s-02` |
| k8s-03 → k8s-16 → prv-22 | k8s-16 | prv-22 | Kubelet Client Cert → Node Secret Read | `scenarios/k8s/runc-cve-2025-52881` | 工作负载—节点运行时边界 | B5 节点可信接口或凭据滥用 | `k8s-03` |
| k8s-05 → k8s-17 → prv-24 | k8s-17 | prv-24 | Node Artifact Consumer → Weak-Label Service Takeover | `scenarios/k8s/gitrepo-cve-2024-10220` | 工作负载—节点运行时边界 | B6 节点侧可信内容替换 | `k8s-05` |
| k8s-11 → k8s-18 → prv-16 | k8s-18 | prv-16 | Privileged Container Breakout | `scenarios/k8s/privileged-breakout` | 工作负载—节点运行时边界 | B3 危险工作负载隔离配置 | `k8s-11` |
| k8s-12 → k8s-19 → prv-15 | k8s-19 | prv-15 | hostPath Writable Mount Escape | `scenarios/k8s/hostpath-escape` | 工作负载—节点运行时边界 | B2 宿主路径与符号链接越界 | `k8s-12` |
| k8s-14 → k8s-20 → prv-17 | k8s-20 | prv-17 | CAP_SYS_ADMIN cgroup Escape | `scenarios/k8s/cap-sys-admin-cgroup` | 工作负载—节点运行时边界 | B3 危险工作负载隔离配置 | `k8s-14` |
| k8s-17 → k8s-21 → prv-20 | k8s-21 | prv-20 | Docker Socket Mount Escape | `scenarios/k8s/docker-socket-escape` | 工作负载—节点运行时边界 | B4 运行时控制接口暴露 | `k8s-17` |
| k8s-23 → k8s-22 → prv-18 | k8s-22 | prv-18 | hostPID ProcFS Host Filesystem Access | `scenarios/k8s/seccomp-bypass` | 工作负载—节点运行时边界 | B3 危险工作负载隔离配置 | `k8s-23` |
| cloud-02 → k8s-31 → k8s-23 → prv-27 | k8s-23 | prv-27 | CAP_NET_RAW → Private-Cloud Metadata MITM | `scenarios/k8s/cap-netraw-metadata` | 工作负载可达与放置边界 | C1 网络路径与地址操纵 | `cloud-02` |
| k8s-33 → k8s-24 → prv-19 | k8s-24 | prv-19 | Multi-Tenant K8s: Container Escape → Cross-Tenant Access | `scenarios/k8s/multi-tenant-k8s` | 工作负载—节点运行时边界 | B3 危险工作负载隔离配置 | `k8s-33` |
| cloud-06 → k8s-37 → k8s-25 → prv-21 | k8s-25 | prv-21 | Managed Notebook Escape → Cluster ServiceAccount Token Theft | `scenarios/k8s/notebook-escape` | 工作负载—节点运行时边界 | B4 运行时控制接口暴露 | `cloud-06` |
| cloud-17 → k8s-47 → k8s-26 → prv-23 | k8s-26 | prv-23 | K8s Host-Agent Channel → Node Bootstrap Secrets | `scenarios/k8s/wireserver-bootstrap` | 工作负载—节点运行时边界 | B5 节点可信接口或凭据滥用 | `cloud-17` |
| cloud-19 → k8s-49 → k8s-27 → prv-25 | k8s-27 | prv-25 | Malicious Model Loading → Inference Pod → Node Metadata | `scenarios/k8s/pickle-model` | 工作负载—节点运行时边界 | B7 不可信工作负载代码执行 | `cloud-19` |
| k8s-22 → k8s-28 → prv-28 | k8s-28 | prv-28 | Service ExternalIP Traffic Interception | `scenarios/k8s/externalip-hijack` | 工作负载可达与放置边界 | C1 网络路径与地址操纵 | `k8s-22` |
| k8s-27 → k8s-29 → prv-30 | k8s-29 | prv-30 | NetworkPolicy Label Spoofing Bypass | `scenarios/k8s/networkpolicy-bypass` | 工作负载可达与放置边界 | C2 网络策略选择器欺骗 | `k8s-27` |
| k8s-28 → k8s-30 → prv-31 | k8s-30 | prv-31 | Node Selector Evasion | `scenarios/k8s/node-selector-evasion` | 工作负载可达与放置边界 | C3 调度约束绕过 | `k8s-28` |
| k8s-29 → k8s-31 → prv-32 | k8s-31 | prv-32 | Toleration Abuse (Taint Bypass) | `scenarios/k8s/toleration-abuse` | 工作负载可达与放置边界 | C3 调度约束绕过 | `k8s-29` |
| k8s-30 → k8s-32 → prv-29 | k8s-32 | prv-29 | CNI IP Spoofing (NetworkPolicy Bypass) | `scenarios/k8s/cni-ip-spoof` | 工作负载可达与放置边界 | C1 网络路径与地址操纵 | `k8s-30` |
| cloud-13 → k8s-43 → k8s-33 → prv-33 | k8s-33 | prv-33 | Managed PostgreSQL FDW Host File Read → Platform Credentials | `scenarios/k8s/rds-logfdw` | 托管平台租户边界 | D1 托管数据库文件系统越界 | `cloud-13` |
| cloud-14 → k8s-44 → k8s-34 → prv-34 | k8s-34 | prv-34 | Managed PostgreSQL Engine Patch: Index Function Runs as Platform Role → Host RCE | `scenarios/k8s/cloudsql-index-rce` | 托管平台租户边界 | D2 托管数据库宿主执行 | `cloud-14` |
| cloud-15 → k8s-45 → k8s-35 → prv-35 | k8s-35 | prv-35 | Shared Integration Runtime → Cross-Tenant Credentials | `scenarios/k8s/synlapse-ir` | 托管平台租户边界 | D3 共享运行时隔离缺陷 | `cloud-15` |
| cloud-27 → k8s-56 → k8s-36 → prv-36 | k8s-36 | prv-36 | Low-Code Connector Secrets via Private Control Plane | `scenarios/k8s/lowcode-secrets` | 托管平台租户边界 | D4 平台控制面租户作用域缺失 | `cloud-25` |
| cloud-31 → k8s-60 → k8s-37 → prv-37 | k8s-37 | prv-37 | Persistence-as-a-Service: Managed Automation Backdoor | `scenarios/k8s/persistence-as-a-service` | 托管平台租户边界 | D5 托管自动化持久化 | `cloud-31` |
| k8s-09 → k8s-38 → prv-38 | k8s-38 | prv-38 | Private Registry Poisoning | `scenarios/k8s/registry-poison` | 云原生供应链信任边界 | E1 镜像仓库写入与可变引用 | `k8s-09` |
| k8s-15 → k8s-39 → prv-39 | k8s-39 | prv-39 | Mutable Image Tag Supply Chain | `scenarios/k8s/mutable-image-tag` | 云原生供应链信任边界 | E1 镜像仓库写入与可变引用 | `k8s-15` |
| cloud-18 → k8s-48 → k8s-40 → prv-40 | k8s-40 | prv-40 | Internal Build Fleet + Private Registry Supply-Chain Overwrite | `scenarios/k8s/buildfleet-registry` | 云原生供应链信任边界 | E2 共享构建链滥用 | `cloud-18` |

### Reserve set: `prv-41..prv-60`

Reserve scenarios only change prefix; their legacy category is retained for
historical traceability.

| Current `k8s` ID | New `prv` ID | Scenario | Path | Legacy category |
|---|---|---|---|---|
| k8s-41 | prv-41 | SSRF to Instance Metadata Credential Theft | `scenarios/k8s/ssrf-to-imds` | 身份、授权与信任 (`identity_trust`) |
| k8s-42 | prv-42 | etcd Unauthorized Access | `scenarios/k8s/etcd-unauth` | 控制面与组件暴露 (`control_plane_exposure`) |
| k8s-43 | prv-43 | SA Token Cross-Namespace Lateral | `scenarios/k8s/sa-cross-ns` | 身份、授权与信任 (`identity_trust`) |
| k8s-44 | prv-44 | CRI Socket Mount Escape | `scenarios/k8s/cri-socket-escape` | 容器与节点边界 (`container_node_boundary`) |
| k8s-45 | prv-45 | SA Token Cluster-Admin Escalation | `scenarios/k8s/sa-cluster-admin` | 身份、授权与信任 (`identity_trust`) |
| k8s-46 | prv-46 | CAP_SYS_PTRACE Host Process Injection | `scenarios/k8s/cap-sys-ptrace-inject` | 容器与节点边界 (`container_node_boundary`) |
| k8s-47 | prv-47 | Serverless Code Injection → IAM PassRole | `scenarios/k8s/lambda-passrole` | 身份、授权与信任 (`identity_trust`) |
| k8s-48 | prv-48 | Private CI/CD Pipeline Poisoning → Secret Exfiltration | `scenarios/k8s/ci-poisoning` | 供应链 (`supply_chain`) |
| k8s-49 | prv-49 | OIDC Claim Mismatch → Cross-Project AssumeRole | `scenarios/k8s/oidc-federation` | 身份、授权与信任 (`identity_trust`) |
| k8s-50 | prv-50 | Managed Notebook Front-End → Cross-Tenant RCE | `scenarios/k8s/cosmiss-notebook` | 托管服务与多租户 (`managed_services_multitenancy`) |
| k8s-51 | prv-51 | Managed DB Internal Subnet + CN Validation Bypass | `scenarios/k8s/extrareplica-repl` | 网络与调度 (`network_scheduling`) |
| k8s-52 | prv-52 | Predictable Volume ID + Missing Ownership Check | `scenarios/k8s/attachme-volume` | 托管服务与多租户 (`managed_services_multitenancy`) |
| k8s-53 | prv-53 | Directory Actor Token: Cross-Tenant Identity Confusion | `scenarios/k8s/actor-token` | 身份、授权与信任 (`identity_trust`) |
| k8s-54 | prv-54 | Platform Middleware Unauth Management Channel → VM Root | `scenarios/k8s/omigod-agent` | 容器与节点边界 (`container_node_boundary`) |
| k8s-55 | prv-55 | IAM Enumeration 2.0: Unlogged AccessDenied Oracle | `scenarios/k8s/iam-enum-oracle` | 身份、授权与信任 (`identity_trust`) |
| k8s-56 | prv-56 | Private Service Catalog Beta Endpoint: Invisible Write | `scenarios/k8s/beta-endpoint` | 托管服务与多租户 (`managed_services_multitenancy`) |
| k8s-57 | prv-57 | Resource Explorer: Feature-Inherent Quiet Enumeration | `scenarios/k8s/resource-explorer` | 托管服务与多租户 (`managed_services_multitenancy`) |
| k8s-58 | prv-58 | Shared NAT Egress: Source-IP Allowlist Bypass | `scenarios/k8s/shared-nat` | 网络与调度 (`network_scheduling`) |
| k8s-59 | prv-59 | Managed Data Workflow → Cross-Tenant Path Traversal | `scenarios/k8s/dataform-pt` | 托管服务与多租户 (`managed_services_multitenancy`) |
| k8s-60 | prv-60 | Serverless Default Service Account: Platform Identity Escalation | `scenarios/k8s/serverless-sa` | 身份、授权与信任 (`identity_trust`) |
