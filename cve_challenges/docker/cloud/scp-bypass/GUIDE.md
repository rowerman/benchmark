# CLOUD-15 SCP 绕过：旧版 API 版本

## 场景概述
服务控制策略（SCP）限制了 AssumeRole AdminRole。旧版 API 版本
（如 2010-05-08）的解析路径没有执行 SCP 校验，攻击者用旧版
请求即可绕过限制获得管理角色。

## 教材锚点
- 案例：SCP 强制缺口（控制面策略执行不一致）
- 平面：控制面（策略执行）→ 失败边界：身份/策略
- 六镜头：MAGIC（策略执行依赖 API 版本路由）；DETECTION（绕过后
  的调用与正常调用同形）

## 前置知识
- SCP 与服务控制策略执行模型；API 版本兼容性

## 利用步骤
1. 用默认版本 AssumeRole AdminRole——被 SCP 拒绝。
2. 在请求中加入旧版参数 `Version=2010-05-08` 重试。
3. 旧版路径未执行 SCP 校验，成功获得 AdminRole 凭据与 flag。

## Flag
`flag{cloud-15-...}`（AdminRole 可访问资源）

## 修复建议
策略执行必须在所有 API 版本路径上一致；废弃旧版端点或统一鉴权
中间件。
