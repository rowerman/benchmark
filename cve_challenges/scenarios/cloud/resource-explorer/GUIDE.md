# CLOUD-25 Resource Explorer：静默枚举

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-25 |
| 名称 | Resource Explorer: Feature-Inherent Quiet Enumeration |
| 技术/CVE | N/A (unlogged search API, case #148) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10636 |

## 场景概述
资源搜索服务（Resource Explorer）会索引租户内全部资源，但搜索操作
本身不产生任何审计事件（feature-inherent 盲区）。攻击者用它一次性
摸清账号的资源拓扑，再精确定位敏感资源（flag-store），全程日志为空。

## 教材锚点
- 案例：Enumerating AWS the quiet way: Resource Explorer（#148）
- 平面：控制面（搜索 API）→ 失败边界：检测（特性固有盲区）
- 六镜头：DETECTION（搜索 API 不产事件，且无法通过客户配置补上）；
  SHARED（资源索引聚合了所有资源元数据）

## 前置知识
- 资源搜索/探索类服务的审计覆盖差异

## 利用步骤
1. 用空查询/关键词（prod、role、flag）调用 `/search`，枚举全部资源。
2. 搜索只返回资源元数据（不含 secret）；发现 `flag-store` 后，携带
   调用者上下文（`X-Caller-ARN`）请求 `/resources/s-001` 读取详情，
   获得 flag；缺少调用者上下文时返回 403。
3. 检查 `/logs`：审计为 0，枚举不可见。

## Flag
`flag{cloud-25-flag-store}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Cloud resource explorer/search API and tenant inventory |
| 侦察与前置条件 | Search query semantics and audit visibility |
| 核心漏洞与利用 | Enumerate resources through the feature-inherent quiet API |
| 权限、横向或影响 | Stealthy cloud resource discovery |
| 验证 | Use discovered resource metadata to recover the flag |

## 修复建议
搜索 API 也应记录操作者与查询；敏感资源（凭据存储）不应出现在
默认索引中。
