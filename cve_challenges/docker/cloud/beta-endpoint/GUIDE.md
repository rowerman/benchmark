# CLOUD-35 Service Catalog：非生产端点不可见写

## 场景概述
云控制台页面的 CSP 头泄露了非生产（beta/gamma）端点
`aws242-servicecatalog-beta`。该端点接受与生产相同的普通凭据，
执行真实的写操作，却完全不产生审计事件——"不可见变更"。

## 教材锚点
- 案例：Bypassing CloudTrail in AWS Service Catalog（#154）
- 平面：控制面（写操作）→ 失败边界：检测（日志路由）
- 六镜头：DETECTION（beta 端点绕过生产日志管线）；MAGIC（非生产
  基础设施与生产共享凭据）

## 前置知识
- 控制台 CSP 头可泄露内部端点；非生产环境的审计盲区

## 利用步骤
1. 读取控制台页面源码，从 CSP `connect-src` 中发现 beta 端点。
2. 携带普通凭据（模拟 SigV4 签名）POST `/portfolios` 到 beta 端点——
   创建成功，响应直接包含 flag。
3. 查询 `/logs`：审计记录数为 0，写操作完全不可见。

## Flag
`flag{cloud-35-invisible-write}`

## 修复建议
非生产端点必须走同一审计管线；CSP 不应暴露内部域名；beta 端点
不得接受生产凭据执行真实写操作。
