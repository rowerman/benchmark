# 自建 Benchmark 与开源 Benchmark 对比分析

本文对比分析 `benchmarks/cve_challenges/`（自建）与 `benchmark_open/` 下 9 个开源基准靶场的优劣势。

---

## 一、开源 Benchmark 概览

| 项目 | 领域 | 场景数 | 部署方式 | 核心特点 |
|------|------|:---:|---------|---------|
| **GOAD** | AD 域渗透 | 7 套完整 AD 环境 | Vagrant + Ansible | 多域森林、Windows VM、最真实的 AD |
| **cloudgoat** | AWS 云安全 | ~30 | Terraform（需 AWS 账号） | 真实 AWS 环境、Rhino Security 维护 |
| **GCPGoat** | GCP 云安全 | ~15 | Terraform（需 GCP 账号） | 真实 GCP 环境、IAM/SQL/GKE 全覆盖 |
| **TerraformGoat** | 多云安全 | ~22 | Terraform（多云） | 覆盖 6 个云 + K8s、但每云仅 2-4 场景 |
| **kubernetes-goat** | K8s 安全 | 15 | kubectl apply | K8s 原生部署、Madhu Akula 维护 |
| **metarget** | 容器/内核/K8s | 62 | CLI 工具 + Docker | 内核 CVE 最多（20 个）、中文社区 |
| **cicd-goat** | CI/CD 安全 | ~10 | Docker Compose | CI/CD 独特覆盖、多 CI 系统 |
| **PACEbench** | Web + 防御 + 链 | 18 CVE + 5 链 + 防御 | Docker Compose | 攻击链支持、防御变体、双语文档 |
| **XBOW** | Web 漏洞 | 104 | 多种 | 竞赛靶场、大量 Web 场景、1 年更新周期 |

---

## 二、自建 Benchmark 概览

| 维度 | 数据 |
|------|------|
| 单点场景 | **101 个**（10 个领域） |
| 攻击链 | **34 条**（跨域混合） |
| 部署方式 | 纯 Docker Compose / KIND / Samba AD |
| 端口管理 | 统一注册表（10000-14000） |
| Flag 系统 | 统一格式（`flag{id-hex}`）+ 验证脚本 |
| 难度分级 | L1 / L2 / L3 三级 |
| 文档体系 | 单场景 ation doc + 聚合 BENCHMARK_SUMMARY.md |
| 质量保障 | Healthcheck 强制要求、nmap 服务检测规则、构建测试 |

### 自建 Benchmark 场景分布

| 领域 | 场景数 | 说明 |
|------|:---:|------|
| Web 应用漏洞 | 18 | SSRF/SSTI/XXE/JWT/GraphQL/PHP 反序列化/XSS/SQLi + WAF 变体 |
| Linux 提权 | 9 | SUID/Docker Socket/Capability/Cron/Polkit/LD_PRELOAD/Passwd |
| 数据库 | 9 | PostgreSQL/MySQL/Oracle/MSSQL/Redis/MongoDB/Elasticsearch/CouchDB NoSQLi |
| Kubernetes | 26 | 逃逸/RBAC/hostPath/etcd/供应链/Webhook/NetworkPolicy |
| Active Directory | 21 | Samba 兼容：Kerberoasting/AS-REP/DCSync/PTH/Silver/Golden/RBCD/Shadow/ACL/Delegation |
| Cloud (LocalStack) | 8 | S3/IAM/SSRF-IMDS/Lambda/DynamoDB/SQS/STS/KMS |
| CI/CD | 5 | PPE/Exposed .git/Hardcoded Secrets/Webhook/Build Arg |
| 网络攻击 | 3 | ARP Spoofing/DNS Exfiltration/Container Sniffing |
| 防御规避 | 5 | WAF Bypass/Log Clear/Process Hide/Timestomp/LoL |
| **合计** | **101** | + 34 条攻击链 |

---

## 三、自建 Benchmark 的优势

### 1. 领域覆盖广度 — 远超任何单一开源项目

```
自建:   Web ■  DB ■  Linux ■  K8s ■  AD ■  Cloud ■  CI/CD ■  Defense ■  Network
GOAD:   AD ■
cloudgoat:  Cloud ■
kube-goat:  K8s ■
metarget:   Linux ■  K8s ■
cicd-goat:  CI/CD ■
PACEbench:  Web ■  Defense ■
```

没有任何一个开源项目同时覆盖 Web、Linux、K8s、AD、Cloud、CI/CD 六大攻击面。最接近的是 metarget（Linux+K8s）和 TerraformGoat（多 Cloud），但都不涉及 AD 或 CI/CD。

### 2. 攻击链 — 差异化核心能力

- **自建**：34 条攻击链，跨 Web→Linux→K8s、Web→Cloud、Cloud→Cloud、Web→DB→AD 等多种组合
- **PACEbench**：5 条 FullChain，全部为 Web→Web（多个 Web CVE 串联）
- **GOAD**：AD 环境内部有天然的攻击路径，但没有显式的"链"概念
- **其他**：均无攻击链概念

自建的攻击链使用统一的每步 flag 机制（`flag{chain<N>-step<M>-descriptor}`），通过 `deploy.sh` 编排不同基础设施类型（Docker + KIND + AD DC），这是独有的设计。

### 3. 零成本、零外部依赖部署

| 项目 | 部署成本 |
|------|---------|
| **自建** | Docker + KIND（本地，零成本） |
| GOAD | Vagrant + VirtualBox（需大量 RAM，Windows 授权） |
| cloudgoat | AWS 账号 + Terraform（产生云费用） |
| GCPGoat | GCP 账号 + Terraform（产生云费用） |
| TerraformGoat | 多云账号（AWS+Azure+GCP+Aliyun...） |
| metarget | 部分场景需 Vagrant + 多 VM |

自建 Benchmark 全部使用 Docker / KIND 本地化部署，不需要任何云账号、外部网络或商业授权。这对 LLM 自动化评测至关重要——可以无限次重复部署和销毁而无需担心成本。

### 4. 统一的质量标准体系

- **Healthcheck 强制要求**：每个 Docker Compose 服务都有 healthcheck，确保场景就绪后再开始测试
- **nmap 服务检测规范**（Rule 3）：要求每个端口 `nmap -sV` 显示正确服务名（非 `tcpwrapped`），通过 `fix-nmap-tcpwrapped.sh` 解决 Docker iptables 问题
- **端口注册表**（Rule 2）：10000-14000 范围统一分配，按领域分块，避免冲突
- **Flag 格式统一**：`flag{scenario-id-hex}` + `scripts/verify-flag.sh` 验证

开源项目中：
- cloudgoat 有良好的 `manifest.yml` 格式，但无 healthcheck 或 nmap 规范
- PACEbench 有 flag.txt 但无统一验证
- metarget 单点场景之间质量差异大
- kubernetes-goat 有基本场景描述但无系统化质量标准

### 5. 文档标准化

每个场景遵循 IRON RULE 的 6 部分结构：
```
Overview → Attack Path Summary → Prerequisites (Knowledge + Tools) 
→ Step-by-Step Exploitation → Flag Location → Verification Commands
```

其中 **Prerequisites 的 Knowledge + Tools 双栏**是独特设计——明确区分"需要理解什么"和"需要用什么工具"，这在所有对比的开源项目中独一无二。

### 6. 防御层与反检测

自建包含 5 个专门的防御规避场景（DEF-01~05），覆盖 WAF 绕过、日志清除、进程隐藏、时间戳恢复、LoTL 滥用。PACEbench 虽有防御场景但挂载在具体 CVE 场景上，而非独立的防御技术评估。

### 7. 场景可组合性（Modular Design）

每个单点场景自包含（独立目录 + Dockerfile + compose），通过 `scenarios.yaml` 注册后即可被攻击链的 `deploy.sh` 编排引用。新增场景不会影响已有场景。

---

## 四、自建 Benchmark 的不足

### 1. 无真实云环境

**问题**：所有 Cloud 场景使用 LocalStack 模拟 AWS。LocalStack 与真实 AWS 存在差异：
- API 覆盖不全（某些高级功能不支持）
- 行为不是 100% 一致（IAM 策略评估、服务限流等）
- 无法模拟跨账号攻击（同一 LocalStack 实例内的所有资源在同一"账号"下）

**对比**：cloudgoat 在真实 AWS 上运行，攻击者实际操作 S3/IAM/Lambda/EC2 的真实 API。TerraformGoat 支持 AWS + Azure + GCP + Aliyun + HuaweiCloud + TencentCloud 六云。

**影响**：对 LLM 测试而言，LocalStack 足以覆盖 API 交互层面的评估，但对"识别真实云环境特征"（如 IMDS、CloudTrail 日志、Org 层级结构）的评估不足。

### 2. AD 场景缺乏 Windows 真实环境

**问题**：全部 21 个 AD 场景基于 Samba AD DC（Docker 容器），而非真实 Windows Server。

- 无 Windows 原生特性（Group Policy、NetLogon 脚本、RDP、WinRM、PowerShell Remoting）
- Samba 的某些 AD 行为与 Windows AD 不一致（Kerberos PAC、委派细节、Schema 扩展）
- 无法使用 Windows 原生的攻击工具（Mimikatz、Rubeus、BloodHound 的 Windows 特定功能）

**对比**：GOAD 使用完整的 Windows Server Evaluation VM（Vagrant），提供最真实的 AD 攻击面——包括 Group Policy、NTLM Relay、跨域信任、证书服务（AD CS）、SCCM 等。

**影响**：Samba 足以覆盖基本的 Kerberos/LDAP/DCSync 攻击路径，但对 AD CS 攻击（ESC1-13）、跨森林攻击、NTLM Relay 等高级攻击面的评估缺失。

### 3. 缺少内核级漏洞场景

**问题**：Linux 提权场景全部是配置错误或用户态 CVE（SUID、Docker Socket、Capability、Polkit CVE-2021-4034），没有内核漏洞。

**对比**：metarget 有 20 个内核 CVE 场景（DirtyCow、DirtyPipe、OverlayFS、Netfilter 等），覆盖从 Linux 2.6 到 5.x 的多个内核版本。

**影响**：内核漏洞利用需要不同的技能组合（内核模块编译、内存布局分析、ROP 链构建），当前 Benchmark 无法评估 LLM 在这方面的能力。

### 4. KIND 单节点 K8s 的局限

**问题**：所有 26 个 K8s 场景使用单节点 KIND 集群（1 control-plane 兼 worker）。

- 无法模拟真实的多节点调度（Pod 调度策略、nodeSelector、affinity）
- 网络插件行为简化（CNI 在单节点上的行为与多节点不同）
- 无 LoadBalancer Service 的真实实现
- NodePort 直接在 localhost 暴露，缺乏多跳网络拓扑

**对比**：kubernetes-goat 支持多种 K8s 平台部署（minikube、EKS、GKE、AKS）。metarget 的多节点支持更完善。GOAD 的多 VM 环境模拟真实的企业网络拓扑（多个子网、域控制器、成员服务器、工作站）。

### 5. CI/CD 场景过于简化

**问题**：CI/CD 场景（CI-01~05）是独立的 Docker 容器，而非真实管道。

**对比**：cicd-goat 提供了完整的 CI/CD 环境——Jenkins Pipeline、Gitea 仓库、GitLab Runner、多种 CI 系统并行运行。

**影响**：当前 CI 场景无法评估"识别真实 CI/CD 管道特征"的能力（Pipeline as Code 语法、Runner 日志、Webhook 签名验证等）。

### 6. 缺乏自动化评分系统

**问题**：目前 flag 验证依赖手动 `verify-flag.sh`，没有内置的自动化评分/进度追踪。

**对比**：
- cloudgoat 有 `cloudgoat.py <scenario>` CLI 管理整个生命周期
- XBOW 有竞赛评分系统
- PACEbench 有 adapter 模式（FastAPI server 4 个端点）

**影响**：对于 LLM 自动化评测，无法直接获取"当前完成了哪些步骤"的进度信息。

### 7. 社区验证与打磨不足

**问题**：自建 Benchmark 为内部开发，尚未经过外部社区的使用和反馈。

**对比**：
- cloudgoat：Rhino Security Labs 维护，GitHub 2.8k+ stars，多年社区反馈
- GOAD：2000+ stars，活跃 Discord，安全培训中广泛使用
- kubernetes-goat：4k+ stars，K8s 安全培训事实标准
- metarget：中文社区活跃，多次大会分享

**影响**：自建场景可能存在未被发现的稳定性问题（如 CI-05 的构建超时），需要通过更多测试迭代来达到生产级别。

### 8. 文档仅支持单语言

**问题**：所有文档仅提供英文版本。

**对比**：PACEbench 提供双语（中英文）README 和利用文档。metarget 的 writeup 有中文版本。

### 9. 缺少可视化 / UI 界面

**问题**：无 Web UI 或交互式界面，全部通过 CLI 操作。

**对比**：kubernetes-goat 有 `kubernetes-goat-home` Web 界面展示所有场景。XBOW 有 竞赛 Web 平台。GOAD 有拓扑图展示 AD 环境。

---

## 五、差距弥补建议

| 不足 | 严重程度 | 改进方案 |
|------|:---:|------|
| 无真实云环境 | 中 | 保持 LocalStack 为主，补充 1-2 个真实 AWS 链（可选） |
| AD 非 Windows | 中 | 保持 Samba 低成本优势，在文档中标注已知差异 |
| 缺少内核 CVE | 低 | 后续可选添加 3-5 个经典内核 CVE（DirtyPipe, OverlayFS） |
| KIND 单节点 | 低 | 为关键场景增加多节点 KIND 配置 |
| CI/CD 简化 | 低 | 参考 cicd-goat 增加 1-2 个完整管道场景 |
| 无自动化评分 | 高 | 最高优先级——设计 adapter 模式和进度反馈 API |
| 社区验证不足 | 中 | 开放测试，收集反馈 |
| 单语言文档 | 低 | 后续可选中文版本 |
| 无可视化 | 低 | 可选 Web 面板展示场景拓扑 |

---

## 六、总结

**自建 Benchmark 的核心竞争力：**

1. **领域覆盖最广**——唯一同时覆盖 Web/Linux/K8s/AD/Cloud/CI/CD/Defense/Network 8 个攻击面的基准
2. **攻击链体系**——34 条跨域攻击链是独有设计，其他开源项目无此概念
3. **零成本部署**——纯 Docker/KIND 本地化，适合 LLM 无限迭代评测
4. **文档标准化**——Knowledge+Tools 双栏 Prerequisites 在开源项目中独一无二
5. **质量控制**——Healthcheck+nmap+端口注册表+构建测试的 4 层质量体系

**需要向开源项目学习的方向：**

1. **真实环境**（cloudgoat/GOAD 的 AWS/Windows 真实度）
2. **提交打磨**（cloudgoat 的社区反馈、kubernetes-goat 的培训验证）
3. **自动化**（PACEbench 的 adapter 模式、cloudgoat 的 CLI 管理）
4. **内核深度**（metarget 的 20 个内核 CVE）
