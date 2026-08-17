# Session 交接总结（2026-08-16）：公有云 Benchmark 扩充

> 本文件记录本次会话完成的所有工作，供后续会话快速恢复上下文。
> 仓库根目录：`C:\Users\hanwenZ\Desktop\小论文\benchmark`（Windows / PowerShell）

## 1. 会话目标

为 DARWIN 自动化渗透测试 benchmark 靶场新增公有云场景：
- **20 个公有云单点场景 + 8 条攻击链**，标识码 `cloud`
- 场景必须真实体现公有云攻击特点（control plane + data plane），**不能是换皮 web/db**
- 全部用多容器（docker compose）模拟"云供应商 + 多租户"，不依赖真实云

## 2. 网页分析结论（ACSP 教材）

分析了 https://blog.senyuuri.info/acsp/book/index.html（《Attacking Cloud Service Providers》，
13 章 / 275 案例，AWS 117 / Azure 89 / GCP 53）。核心结论：

- 主题是**攻击云供应商本身**（控制面入侵、跨租户隔离破坏），不是单租户渗透测试
- **六镜头**分析框架：PLANE / BOUNDARY / IDENTITY / SHARED / MAGIC / DETECTION
- **五阶段 CSP Kill Chain**：Foothold → Local control → Boundary crossing（定义性一步）→ Provider infrastructure → Blast radius
- 案例数据已抓取到 `%TEMP%\acsp\assets\case-studies-data.js`（275 条），本次场景选点全部锚定真实案例编号

## 3. 批准的方案（Design v2）

方案经用户确认后实施。要点：
- 删除 9 个"换皮/过简/重复"旧场景（R1）
- 新增 20 个场景（S1–S20 = CLOUD-23~42）+ 8 条链（C1–C8 = Chain-49~56）
- 重建 11 条受删除影响的现有链（R2）
- 每个场景目录内必须有 `GUIDE.md`（利用指南，含六镜头）
- 基础镜像只需 3 个（用户已拉取）：`python:3.11-slim`、`postgres:16.6`、`alpine/socat:latest`

## 4. 实施改动清单

### 4.1 新增

**`_infra` 公共组件（4 个，位于 `cve_challenges/docker/cloud/_infra/`）**
| 组件 | 作用 |
|---|---|
| `host-agent` | WireServer 宿主代理通道模拟：无鉴权 goalstate + 调用者自供传输证书换密钥包（混合加密 AES-GCM/RSA-OAEP） |
| `audit-log` | 审计事件收集器（用于日志盲区场景的"零审计"验证） |
| `internal-ca` | 证书颁发，可配 CN 正则（模拟 ExtraReplica 尾部未锚定缺陷） |
| `shared-nat` | 共享出口 NAT，从受信源 IP 网段出网（模拟服务标签信任） |

**20 个新场景（`cve_challenges/docker/cloud/<目录>/`，端口 10623–10642）**

| ID | 目录 | 锚点案例 | 核心机制 |
|---|---|---|---|
| CLOUD-23 | `cosmiss-notebook` | #073 | 托管 notebook 前端凭 forwardingId 跨租户路由 |
| CLOUD-24 | `rds-logfdw` | #015 | 托管 PG log_fdw 宿主文件读取→内部凭据 |
| CLOUD-25 | `cloudsql-index-rce` | #052 | 引擎补丁→索引函数以供应商角色执行→宿主 RCE |
| CLOUD-26 | `synlapse-ir` | #062 | 共享集成运行时 ODBC 注入→co-tenant 凭据 |
| CLOUD-27 | `extrareplica-repl` | #061 | 内部子网 + 证书 CN 缺陷→跨租户流复制 |
| CLOUD-28 | `wireserver-bootstrap` | #255/#184 | 宿主代理通道→节点引导密钥→伪造 node 身份 |
| CLOUD-29 | `buildfleet-registry` | #260 | 构建舰队 RUN 执行 + 内部 registry 无隔离覆盖镜像 |
| CLOUD-30 | `pickle-model` | #091 | 恶意 pickle 模型→推理 pod RCE→节点 IMDS |
| CLOUD-31 | `attachme-volume` | AttachMe | 可预测卷 ID + 属主校验缺失 |
| CLOUD-32 | `actor-token` | #246 | 身份 actor/tenant 校验缺陷跨租户 |
| CLOUD-33 | `omigod-agent` | #057/#087 | 供应商中间件无鉴权管理通道→VM root |
| CLOUD-34 | `iam-enum-oracle` | #134/#137 | 无日志 AccessDenied oracle + AssumeRole 差分枚举 |
| CLOUD-35 | `beta-endpoint` | #154 | CSP 泄露 beta 端点→不可见写 |
| CLOUD-36 | `resource-explorer` | #148 | 搜索 API 特性固有盲区静默枚举 |
| CLOUD-37 | `composer-depconf` | #270 | 依赖混淆：全局命名空间抢注私有包名 |
| CLOUD-38 | `lowcode-secrets` | #249/#197 | 连接器存储控制面跨租户密钥外泄 |
| CLOUD-39 | `shared-nat` | #259 | 共享 NAT 出口源 IP 白名单绕过 |
| CLOUD-40 | `dataform-pt` | #267 | 托管数据服务跨租户路径穿越 |
| CLOUD-41 | `serverless-sa` | #266/#272 | 无服务器默认服务账号提权 |
| CLOUD-42 | `persistence-as-a-service` | #149 | 托管自动化 runbook 持久化（轮换后仍可访问） |

每个场景 = `app.py`（Flask 模拟）+ `Dockerfile` + `docker-compose.yml` + `GUIDE.md`。
postgres 场景（cloud-24/25/27）用真实 PostgreSQL 16.6。

**8 条新链（`cve_challenges/chains/`，Chain-49~56）**

| 链目录 | chain_id | 步骤 |
|---|---|---|
| `managed-db-lateral` | Chain-49 | cloud-25 → cloud-24 → cloud-27 |
| `chaosdb-lineage` | Chain-50 | cloud-23 → cloud-28 → cloud-31 |
| `ai-serverless-identity` | Chain-51 | cloud-30 → cloud-41 → cloud-32 |
| `middleware-network` | Chain-52 | cloud-33 → cloud-39 → cloud-26 |
| `supply-chain-persistence` | Chain-53 | cloud-29 → cloud-37 → cloud-42 |
| `identity-trust` | Chain-54 | cloud-34 → cloud-13 → cloud-32 → cloud-38 |
| `detection-blindspot` | Chain-55 | cloud-36 → cloud-34 → cloud-35 → cloud-42 |
| `managed-data-lateral` | Chain-56 | cloud-26 → cloud-40 → cloud-25 → cloud-01 |

每条链含 `chain.yaml` + `deploy.sh` + `teardown.sh`。

**GUIDE.md（33 个）**：20 个新场景 + 13 个保留场景全部补齐，模板含场景概述 / 教材锚点+六镜头 / 前置知识 / 利用步骤 / flag / 修复建议。

### 4.2 删除（R1，9 个旧场景）

目录已删：`db-to-imds`(cloud-06)、`s3-monopoly`(cloud-07)、`gateway-smuggling`(cloud-10)、
`passrole-abuse`(cloud-14)、`logging-gap`(cloud-16)、`confused-deputy`(cloud-17)、
`svc-tag-spoof`(cloud-18)、`shared-metadata-proxy`(cloud-20)、`shared-inference-queue`(cloud-22)。

**编号保留空缺不重排**（与 web/db 域惯例一致）。

### 4.3 修改

- `cve_challenges/scripts/scenarios.yaml`：删 9 条、增 20 条（cloud-23~42）
- 11 条现有链重建：cf-to-scp、ci-to-oidc、db-to-cross-account、db-to-passrole、gateway-to-deputy、lambda-to-cross-account、loggap-to-s3-stealth、notebook-to-scp、s3-to-cf、svctag-to-imds-to-deputy、web-to-db-to-cross-account（chain.yaml + deploy/teardown 全部重写；顺带修复了其中几处原本引用错误路径/绝对路径的旧脚本）
- `cve_challenges/scripts/build_benchmark_summary.py`：CLOUD_ORDER 更新
- `cve_challenges/scripts/fix-nmap-tcpwrapped.sh`：端口表删 9 加 20
- `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md`：删被删段落，末尾追加 CLOUD-23~42 指南
- `cve_challenges/docker/cloud/_infra/host-agent/app.py`：RSA 直接加密改混合加密（RSA-OAEP 载荷上限 190B）
- `cve_challenges/docker/cloud/_infra/internal-ca/app.py`：CA 证书加 BasicConstraints(ca=True)（否则 TLS 客户端证书验证报 invalid CA）
- `cve_challenges/docker/cloud/_infra/audit-log/app.py`：补 `app.run()` 启动块（原文件漏了，容器启动即退出）

## 5. 验证结果

**20 个新场景全部实际构建并走通攻击路径，均拿到预期 flag**；验证后容器已 `down -v` 清理。

静态检查全过：
- 80 个 app.py 编译通过
- 全部 compose `docker compose config` 合法
- 新场景端口 10623–10642 唯一无冲突（链端口 11649–11656 预留）
- scenarios.yaml 解析正常（33 个 cloud）；链引用无坏引用；被删场景引用残留为零

## 6. 踩坑记录（下个 session 务必注意）

- **postgres 场景**：init.sql/init-db.sh 只在首次初始化执行，修改后必须 `docker compose down -v` 才生效；postgres 官方镜像**没有 python3**（init 脚本勿用 python）；PG 的 cert 认证不允许 `clientcert=verify-ca`（强制 verify-full）
- **requests 库**不允许多行 header（PEM 证书一律 base64 后放 header，接收端解码）
- **RSA-OAEP** 最大载荷约 190 字节，大 payload 用 AES-GCM + RSA 包裹会话密钥的混合加密
- **攻击者 Web UI 模式**：每个场景暴露一个入口端口，步骤按钮触发攻击链；GUIDE.md 的利用步骤与默认 payload 必须与实际触发条件一致（如 synlapse 注入需 `|; &` 触发字符）
- **Docker daemon**：沙箱内不可访问，需 escalation；`DOCKER_CONFIG` 指向临时目录避免 config 权限报错

## 7. 关键约定与维护信息

- 场景编号空缺合法，新场景从 cloud-43 起（端口 10643+）；链从 Chain-57 起（端口 11657+）
- 删除场景时必须同步清理：scenarios.yaml、fix-nmap-tcpwrapped.sh、build_benchmark_summary.py、docker-scenarios-exploitation.md、所有链的 chain.yaml/deploy.sh/teardown.sh
- 每个 cloud 场景目录必须包含 GUIDE.md；新增场景验收标准含"GUIDE.md 存在且步骤可被攻击路径走通"
- 链的 deploy.sh 逐场景拉起单点 compose（`CVE_FLAG="flag{chain-test}"` 覆盖 flag），teardown 逐场景 `down -v`

## 8. 待办 / 已知限制

- **web/db/k8s 域的 GUIDE.md 尚未补全**（用户要求留到之后）
- k8s 型 cloud 场景（cloud-02/03/19）的 GUIDE 基于 deploy 脚本撰写，未实际起 KIND 集群验证（属既有 k8s 域流程）
- 链（Chain-49~56）只做了静态校验（chain.yaml 引用有效、compose 可解析），**未实际部署整链运行验证**，建议后续跑一遍
- 未提交 git（仓库有大量历史未提交变更，如 BENCHMARK_SUMMARY.md、BENCHMARK_SCENARIOS_OVERVIEW.md 等旧改动）

## 9. 下一个 session 建议

1. 先读本文件 + `cve_challenges/scripts/scenarios.yaml` 的 cloud 段
2. 如需补验证：起一条链（如 Chain-49）跑 deploy.sh 后逐步验证 next_hint
3. 如需继续扩展：按第 7 节约定新增 cloud-43+；web/db/k8s GUIDE.md 补全可作为独立任务
