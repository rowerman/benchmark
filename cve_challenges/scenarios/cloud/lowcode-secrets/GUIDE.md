# CLOUD-27 Silent Reaper：低代码连接器密钥控制面外泄

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-27 |
| 名称 | Silent Reaper: Low-Code Connector Secrets via Control Plane |
| 技术/CVE | N/A (connector store tenant-scope missing, case #249/#197) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10638 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | connector-store 经 flag-vault 交付（network-source：连接器控制面内网地址（跨租户读取）） |

## 场景概述
低代码平台（Logic Apps/API Connections 类）的连接器存储控制面 API
可以跨租户列出连接器并返回其密钥——调用者身份与连接器属主从未校验。
攻击者一次性抽走所有租户的连接器密钥（Silent Reaper / API Connections）。

## 教材锚点
- 案例：Silent Reaper（#249）；API Connections 跨租户（#197）；
  Vault Recon（#250）
- 平面：控制面（连接器存储）→ 失败边界：账号/共享组件
- 六镜头：SHARED（连接器存储是供应商侧共享组件，爆炸半径为所有租户）；
  IDENTITY（列表/读取端点不校验调用者租户）

## 前置知识
- 低代码平台连接器与托管身份模型；控制面 API 的租户 scope

## 利用步骤
1. 调用 `GET /api/connections` 列出连接器——发现 tenant-b 的
   SharePoint 连接器。
2. 调用 `GET /api/connections/conn-1002` 直接读取 secret。
3. secret 中携带 flag。
4. 终端服务 connector-store 向 flag-vault 出示连接器控制面内网地址（跨租户读取），换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 connector-store 向 flag-vault 出示「连接器控制面内网地址（跨租户读取）」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-27-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-27 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-27 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Low-code connector control plane and secret storage |
| 侦察与前置条件 | Connector identifier/tenant scope behavior |
| 核心漏洞与利用 | Request a connector secret outside the caller tenant |
| 权限、横向或影响 | Cross-tenant credential disclosure |
| 验证 | Read the returned connector secret/flag |

## 修复建议
控制面读取必须按调用者租户过滤；连接器密钥不应通过列表/详情 API
返回明文；密钥应加密并短时效轮换。
