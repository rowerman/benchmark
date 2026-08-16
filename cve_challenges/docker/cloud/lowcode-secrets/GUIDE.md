# CLOUD-38 Silent Reaper：低代码连接器密钥控制面外泄

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

## Flag
`flag{cloud-38-connector-secret}`

## 修复建议
控制面读取必须按调用者租户过滤；连接器密钥不应通过列表/详情 API
返回明文；密钥应加密并短时效轮换。
