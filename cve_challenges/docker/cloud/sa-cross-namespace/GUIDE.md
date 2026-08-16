# CLOUD-03 K8s SA Token → 跨命名空间访问

## 场景概述
tenant-a 的 ServiceAccount 被绑定了过宽的 ClusterRole
（可读 pods/exec/secrets 且跨命名空间）。攻击者拿到该 SA token 后
可跨命名空间读取 tenant-b 的 Secret/执行命令。

## 教材锚点
- 案例：托管 K8s 的 RBAC 过度授权（Ch6）
- 平面：控制面（集群 API）→ 失败边界：命名空间/RBAC
- 六镜头：IDENTITY（SA 自动挂载 token）；BOUNDARY（ClusterRoleBinding
  把租户隔离击穿）

## 前置知识
- SA token；RBAC ClusterRole/ClusterRoleBinding；kubectl

## 利用步骤
1. 进入 tenant-a 的 attacker pod，读取挂载的 SA token。
2. 用 token 调用 K8s API 列出/读取 tenant-b 的 Secret。
3. `kubectl get secret -n tenant-b target-flag` 解码得到 flag。

## Flag
`flag{cloud-03-step2-cross-ns}`

## 修复建议
RBAC 遵循最小权限与命名空间内绑定（Role/RoleBinding）；
禁止跨命名空间 ClusterRole 绑定。
