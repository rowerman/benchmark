# PRV-54 平台中间件无鉴权管理通道 → VM Root

## 场景信息

| 字段 | 值 |
|---|---|
| ID | PRV-54 |
| 名称 | Platform Middleware Unauth Management Channel → VM Root |
| 技术/CVE | N/A (auth bypass in platform agent, CVE-2021-38647 lineage) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10633 |
| 入口身份 | 宿主侧黑盒起点（无私有云凭据，需自行派生） |
| 终点 | omi-agent 经 flag-vault 交付（network-source：中间件代理内网地址（未鉴权通道拿到 root 后取）） |

## 场景概述
平台运营方在租户 VM 上部署受管中间件代理，但管理端口不做认证。
攻击者可访问该内部通道并以 root 执行命令，从平台密钥库读取受保护资源。

## 教材锚点
- 案例：OMIGOD（#057/#087）；RHUI（#068）
- 平面：控制面（供应商代理）→ 失败边界：网络 + provider-side
- 六镜头：MAGIC（供应商自动化以 root 运行）；SHARED（代理安装在所有
  租户 VM 上，爆炸半径为"所有租户"）；DETECTION（客户不感知代理存在，
  也无补丁责任）

## 前置知识
- 平台中间件 / 共享责任模型中的盲区
- 无鉴权管理端口的利用

## 利用步骤

1. 扫描内部 VM，发现 vm-b 的 5986 端口开放且 banner 显示 platform middleware agent。
2. 直接 POST `/wsman/exec`（无需任何凭据）执行命令：先确认 root 身份，再从中间件容器里
   向平台密钥库取密文（该密钥库只对 omi-agent 的地址开放）：
   `id; python3 -c "import urllib.request;print(urllib.request.urlopen('http://flag-vault:5000/flag').read().decode())"`
3. 以 root 拿到 VM 上的 flag。

## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 omi-agent 向 flag-vault 出示「中间件代理内网地址（未鉴权通道拿到 root 后取）」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{prv-54-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py prv-54 <flag>`（gate）+
  `python3 tests/cloud/run.py prv-54 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Cloud middleware agent management API and VM services |
| 侦察与前置条件 | Unauthenticated management endpoint discovery |
| 核心漏洞与利用 | Call the vulnerable platform middleware management channel |
| 权限、横向或影响 | VM root-level command execution |
| 验证 | Execute the agent command path to read the flag |

## 修复建议
管理通道必须强认证 + 双向 TLS；平台运营方部署的中间件要纳入客户补丁
可见性；5986 等管理端口不得对租户网络开放。
