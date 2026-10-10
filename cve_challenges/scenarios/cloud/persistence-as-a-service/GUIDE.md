# CLOUD-31 持久化即服务：托管自动化后门

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-31 |
| 名称 | Persistence-as-a-Service: Managed Automation Backdoor |
| 技术/CVE | N/A (automation-runbook persistence, case #149) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10642 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | victim-resource 经 flag-vault 交付（network-source：受保护资源内网地址（密钥轮换校验通过）） |

## 场景概述
攻击者在托管自动化服务注册一个恶意 runbook，脚本以服务身份周期性
从凭据库拉取当前凭据并访问受保护资源。防御方轮换凭据后，runbook
自动重新获取新凭据——持久化访问不依赖任何静态后门（Persistence-
as-a-service）。

## 教材锚点
- 案例：Cloud attacker persistence techniques in AWS（#149）
- 平面：控制面（自动化服务）→ 失败边界：检测/持久化
- 六镜头：MAGIC（托管自动化以服务身份周期运行）；DETECTION（runbook
  混在正常自动化中难以发现）

## 前置知识
- 托管自动化（runbook/定时任务）与托管身份
- 凭据轮换作为检测/清除手段的局限

## 利用步骤
1. 注册恶意 runbook：脚本内容=拉取当前 vault 凭据 → 调用受保护资源
   → 把凭据与 flag 外发到攻击者收集端点。
2. 触发凭据轮换（`POST /rotate`）并同步受保护资源的新密钥。
3. 等待 runbook 下一轮执行（每 5s）——它自动用新凭据再次读到 flag。
4. 终端服务 victim-resource 向 flag-vault 出示受保护资源内网地址（密钥轮换校验通过），换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 victim-resource 向 flag-vault 出示「受保护资源内网地址（密钥轮换校验通过）」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-31-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-31 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-31 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Managed automation, runbooks, credentials, and rotation |
| 侦察与前置条件 | Runbook persistence behavior and credential-vault access after rotation |
| 核心漏洞与利用 | Create a persistent automation runbook/backdoor |
| 权限、横向或影响 | Long-lived access across credential rotation |
| 验证 | Wait for or invoke the runbook and capture the final flag |

## 修复建议
自动化服务要审计 runbook 的来源与内容；托管身份按用途最小化；
轮换之外还要监控异常的周期外发行为；runbook 代码应受代码审查
与签名保护。
