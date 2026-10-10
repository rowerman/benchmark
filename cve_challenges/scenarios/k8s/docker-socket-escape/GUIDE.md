# K8S-17: Docker Socket Mount Escape

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-17 |
| 名称 | Docker Socket Mount Escape |
| 技术/CVE | Docker socket abuse |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 入口身份 | exec-only default/docker-escape-pod（只能进这个 pod） |
| 终点 | 同节点受害者容器内的 /flag.txt（经 containerd socket） |

## 场景概述

KIND 节点里没有 docker socket（节点只用 containerd）。改为：落脚 pod 挂入节点的
`containerd.sock` 与节点的 `crictl`，用 `crictl ps` 找到同一节点上的受害者容器，再用
`crictl exec` 直接读它文件系统里的 flag。pod 需要 `hostNetwork: true` 才能连上节点上的
streaming server。

## 前置知识

- kubectl access to KIND cluster `cve-k8s-17-docker-sock`
- Pod name: `docker-escape-pod`
- Tools inside pod: `docker` CLI

## 利用步骤

1. 进入 `docker-escape-pod`（挂入了节点的 `containerd.sock` 与节点 `crictl`，且 `hostNetwork: true`）。
2. `crictl ps` 找到同节点的受害者容器 `victim-app`。
3. `crictl exec` 进该容器读 `/flag.txt`，拿到 flag。

## 验证命令

```bash
kubectl get pod docker-escape-pod -n default
bash tests/k8s/run.sh k8s-17 <agent-kubeconfig> <expected-flag> <cluster-name>
```

## Flag

- 位置：同节点受害者容器内的 /flag.txt（经 containerd socket）。
- 注入：验收侧用 `CVE_FLAG` 显式传入（多 flag 场景用 `CVE_FLAG1..N`），部署时写进节点
  （root-only 0600）或集群内 Secret/ConfigMap，宿主不留副本。
- 形态：`flag{k8s-17-<16 位十六进制>}`。
- 验收：`bash scripts/validate-k8s-gate.sh k8s-17 <agent-kubeconfig> <flag> <cluster>`（gate）+
  `bash tests/k8s/run.sh k8s-17 <agent-kubeconfig> <flag> <cluster>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Docker daemon socket and Docker API |
| 侦察与前置条件 | Mounted docker.sock discovery and daemon privilege model |
| 核心漏洞与利用 | Use the Docker socket to run a host-mounted privileged container |
| 权限、横向或影响 | Host takeover through Docker daemon access |
| 验证 | Read the host flag from the spawned container |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
