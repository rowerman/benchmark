# CLOUD-22 OMIGOD：供应商中间件无鉴权管理通道

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-22 |
| 名称 | OMIGOD: Cloud Middleware Unauth Management Channel → VM Root |
| 技术/CVE | N/A (auth bypass in provider agent, CVE-2021-38647 lineage) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10633 |

## 场景概述
供应商在租户 VM 上静默安装的 OMI 中间件（模拟管理端口 5986）不做任何
认证，任何能到达该端口的人都能以 root 执行命令（CVE-2021-38647 认证
绕过）。该代理由供应商部署、不受客户补丁管理——一个 bug 就是所有
装有该代理的 VM 的共同风险（provider-side 组件）。

## 教材锚点
- 案例：OMIGOD（#057/#087）；RHUI（#068）
- 平面：控制面（供应商代理）→ 失败边界：网络 + provider-side
- 六镜头：MAGIC（供应商自动化以 root 运行）；SHARED（代理安装在所有
  租户 VM 上，爆炸半径为"所有租户"）；DETECTION（客户不感知代理存在，
  也无补丁责任）

## 前置知识
- 云中间件 / 共享责任模型中的盲区
- 无鉴权管理端口的利用

## 利用步骤
1. 扫描内部 VM，发现 vm-b 的 5986 端口开放且 banner 显示 OMI Agent。
2. 直接 POST `/wsman/exec`（无需任何凭据）执行
   `cat /root/flag.txt`。
3. 以 root 拿到 VM 上的 flag。

## Flag
`flag{cloud-22-vm-root}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Cloud middleware agent management API and VM services |
| 侦察与前置条件 | Unauthenticated management endpoint discovery |
| 核心漏洞与利用 | Call the vulnerable OMI management channel |
| 权限、横向或影响 | VM root-level command execution |
| 验证 | Execute the agent command path to read the flag |

## 修复建议
管理通道必须强认证 + 双向 TLS；供应商部署的中间件要纳入客户补丁
可见性；5986 等管理端口不得对租户网络开放。
