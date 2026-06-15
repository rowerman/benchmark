#!/bin/bash
# fix-nmap-tcpwrapped.sh
# 修复 Docker bridge + iptables NAT 导致的 nmap "tcpwrapped" 问题
# Docker 使用 iptables DNAT + conntrack 处理端口发布，会过滤 nmap 的服务探测包
# 此脚本在 DOCKER-USER chain 插入 ACCEPT 规则（Docker 重启后保留）
# 需要 root/sudo 权限执行
#
# 注意：Samba AD 场景的 TCP 端口通过以下方式解决 tcpwrapped：
#   1. ad-proxy (eager-connect, host network) — 用于 localhost 访问
#   2. configure_samba_for_nmap.sh — 配置 Samba 响应 nmap 探测（直接扫描 DC）
# 此脚本仅需处理 UDP 端口和通过 Docker -p 发布的非 AD TCP 端口。

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] This script requires root. Run with: sudo bash $0"
  exit 1
fi

echo "[*] Fixing nmap tcpwrapped for Docker-published ports..."

# ============================================================
# AD DC (Samba AD) UDP ports
# UDP 端口仍使用 Docker -p 发布，需要通过 iptables 规则
# 避免 tcpwrapped。TCP 端口已通过 ad-proxy (host network)
# 解决，不需要额外 iptables 规则。
# ============================================================
AD_UDP_PORTS=(
  10053   # DNS (UDP)
  10088   # Kerberos (UDP)
  10464   # Kerberos Change/Set Password (UDP)
)

# ============================================================
# AD Service Discovery — HTTP endpoint on DC container
# Docker -p 发布，可能受 iptables 影响
# ============================================================
DISCOVERY_PORTS=(
  10080   # AD service discovery JSON endpoint (on dc01)
)

# ============================================================
# MSSQL scenarios — TDS 协议不发送明文 banner
# ============================================================
MSSQL_PORTS=(
  10119   # MSSQL xp_cmdshell (web/mssql-xp-cmdshell)
  10204   # MSSQL linked server low (db/mssql-linked-server)
  10214   # MSSQL linked server target (db/mssql-linked-server)
)

# ============================================================
# Oracle TNS — TNS Listener 在 Docker NAT 后可能被误判
# ============================================================
ORACLE_PORTS=(
  10203   # Oracle TNS (db/oracle-tns)
)

# ============================================================
# Cloud scenarios — attacker-facing web ports (Docker -p published)
# ============================================================
CLOUD_WEB_PORTS=(
  10601   # cloud-01 ssrf-to-imds
  10604   # cloud-04 lambda-passrole
  10605   # cloud-05 cf-injection
  10606   # cloud-06 db-to-imds
  10607   # cloud-07 s3-monopoly
  10608   # cloud-08 ci-poisoning
  10609   # cloud-09 notebook-escape
  10610   # cloud-10 gateway-smuggling
  10611   # cloud-11 oidc-federation
  10612   # cloud-12 cross-account-trust
  10613   # cloud-13 golden-saml
  10614   # cloud-14 passrole-abuse
  10615   # cloud-15 scp-bypass
  10616   # cloud-16 logging-gap
  10617   # cloud-17 confused-deputy
  10618   # cloud-18 svc-tag-spoof
  10620   # cloud-20 shared-metadata-proxy
  10621   # cloud-21 global-s3-squatting
  10622   # cloud-22 shared-inference-queue
)

# ============================================================
# Cloud scenarios — internal service socat proxy ports
# ============================================================
CLOUD_PROXY_PORTS=(
  10701   # IMDS proxy
  10702   # IAM/STS proxy
  10703   # OIDC IdP proxy
  10704   # S3 simulator proxy
  10705   # Lambda simulator proxy
  10706   # PostgreSQL proxy
  10707   # SAML IdP proxy
)

ALL_TCP_PORTS=("${DISCOVERY_PORTS[@]}" "${MSSQL_PORTS[@]}" "${ORACLE_PORTS[@]}" "${CLOUD_WEB_PORTS[@]}" "${CLOUD_PROXY_PORTS[@]}")

added=0
skipped=0

# ── UDP ports (AD Kerberos, DNS, KDC) ────────────────────────────
for port in "${AD_UDP_PORTS[@]}"; do
  if ! iptables -C DOCKER-USER -p udp --dport "$port" -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -p udp --dport "$port" -j ACCEPT
    echo "  + ACCEPT udp/$port"
    ((added++))
  else
    ((skipped++))
  fi
done

# ── TCP ports (discovery, MSSQL, Oracle) ─────────────────────────
# AD TCP ports are handled by ad-proxy (eager-connect, host network)
# so they don't need iptables rules here.
for port in "${ALL_TCP_PORTS[@]}"; do
  if ! iptables -C DOCKER-USER -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    echo "  + ACCEPT tcp/$port (conntrack: NEW,ESTABLISHED,RELATED)"
    ((added++))
  else
    ((skipped++))
  fi
done

echo ""
echo "[+] Done: $added rules added, $skipped already present"
echo ""
echo "    Verify with: sudo iptables -L DOCKER-USER -n -v"
echo "    Remove rules with: sudo iptables -F DOCKER-USER"
echo ""
echo "    Note: DOCKER-USER chain persists across Docker restarts."
echo "    These rules allow full nmap probe traffic to the listed ports,"
echo "    preventing the 'tcpwrapped' false positive in service detection."
