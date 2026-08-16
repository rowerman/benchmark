# CLOUD-19 多租户 K8s：容器逃逸 → 跨租户访问

## 场景概述
模拟 Azurescape 式跨租户攻击：tenant-a 的 pod 是特权容器
（privileged + hostPID + hostNetwork）。攻击者从容器逃逸到共享
KIND 节点，再借节点上挂载的 SA token 横向进入 tenant-b 的 pod。

## 教材锚点
- 案例：Azurescape（#054）；GKE Autopilot 逃逸（Ch6 Level 3）
- 平面：数据面（容器）→ 节点 → 集群；失败边界：命名空间/宿主
- 六镜头：SHARED（多租户共享同一节点）；IDENTITY（节点上其他
  pod 的 SA token 可被读取）

## 前置知识
- 特权容器逃逸（nsenter）；hostPID/hostNetwork；SA token 窃取

## 利用步骤
1. 进入 tenant-a 的 attacker pod。
2. `nsenter --target 1 --mount --uts --ipc --net --pid -- sh`
   逃逸到节点。
3. 读取节点上 pod 挂载的 SA token，用其调用 K8s API。
4. 对 tenant-b 的 target pod 执行 exec，读取环境变量中的 flag。

## Flag
`flag{cloud-19-cross-tenant}`（tenant-b target pod 环境）

## 修复建议
禁用特权容器；节点隔离租户工作负载；禁止 hostPID/hostNetwork；
使用沙箱运行时。
