#!/bin/bash
# configure_samba_for_nmap.sh
# Tweak Samba AD DC configuration so nmap -sV can correctly identify
# AD services (SMB/LDAP/Kerberos/RPC/DNS) on the DC.
#
# Root cause: the services Samba runs are client-speaks-first — they
# expect the client to send the first protocol message.  nmap -sV
# sends a NULL probe first (just opens TCP connection and waits for
# a banner).  When Samba's service gets a connection with no data,
# different things happen depending on the service:
#
#   SMB (445):  Samba >=4.11 defaults to server min protocol=SMB2,
#               rejecting nmap's SMBv1 probe → no response → tcpwrapped
#   LDAP (389): Samba requires SASL or proper BER bind; nmap's simple
#               search probe is rejected → tcpwrapped
#   Kerberos:   Heimdal KDC may not respond to nmap's probe format
#   RPC (135):  Samba DC doesn't run standalone RPC endpoint mapper
#
# This script relaxes Samba's protocol requirements so nmap's built-in
# probes receive recognizable responses.
#
set -e

SMB_CONF=""
for candidate in /etc/samba/smb.conf /usr/local/samba/etc/smb.conf /var/lib/samba/private/smb.conf; do
    if [ -f "$candidate" ]; then
        SMB_CONF="$candidate"
        break
    fi
done

if [ -z "$SMB_CONF" ]; then
    echo "[configure-samba] ERROR: cannot find smb.conf"
    exit 1
fi

echo "[configure-samba] Using smb.conf: $SMB_CONF"

# ── Backup ─────────────────────────────────────────────────────────
cp "$SMB_CONF" "${SMB_CONF}.bak"

# ── Apply nmap-friendly settings ───────────────────────────────────
echo "[configure-samba] Applying nmap-friendly Samba settings..."

set_conf() {
    # set_conf <key> <value> [comment]
    local key="$1" val="$2"
    if grep -qi "^\s*${key}" "$SMB_CONF"; then
        sed -i "s/^\s*${key}\s*=.*/${key} = ${val}/i" "$SMB_CONF"
    else
        sed -i "/^\[global\]/a \    ${key} = ${val}" "$SMB_CONF"
    fi
    echo "  + ${key} = ${val}"
}

# 1. server min protocol = NT1
#    Samba >= 4.11 defaults to SMB2_02 minimum.  nmap's SMB probe uses
#    SMBv1 (NT LM 0.12 dialect).  Without this, Samba rejects the probe
#    and nmap gets no response → tcpwrapped on port 445.
set_conf "server min protocol" "NT1"

# 2. server signing = disabled
#    nmap's SMB probe doesn't sign its request.  If signing is required,
#    Samba drops the connection immediately.
set_conf "server signing" "disabled"

# 3. ntlm auth = yes
#    Allow NTLMv1/NTLMv2 — nmap's probe may use older auth.
set_conf "ntlm auth" "yes"

# 4. restrict anonymous = 0
#    Allow anonymous LDAP binds and SMB session setup for service
#    enumeration (nmap sends anonymous binds/connections).
set_conf "restrict anonymous" "0"

# 5. map to guest = Bad User
#    Don't reject connections with unknown credentials outright.
set_conf "map to guest" "Bad User"

# 6. smb ports = 445 139
#    Ensure both SMB-over-TCP and NetBIOS session ports are active.
set_conf "smb ports" "445 139"

# 7. lanman auth = yes
#    Allow LM authentication (very old dialect, but nmap might probe it).
#    This is the most permissive setting — nmap's SMB probe can use
#    the oldest dialects.
set_conf "lanman auth" "yes"

# ── Verify listening ports ─────────────────────────────────────────
echo "[configure-samba] Verifying Samba service ports..."
sleep 2  # brief wait for service reload

# Check which AD ports Samba is actually listening on
EXPECTED_PORTS="53 88 135 139 389 445 464 636 3268 3269"
LISTENING=""
for port in $EXPECTED_PORTS; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        LISTENING="${LISTENING} ${port}"
    fi
done
echo "[configure-samba] TCP ports listening:${LISTENING}"

MISSING=""
for port in $EXPECTED_PORTS; do
    if ! echo "$LISTENING" | grep -qw "$port"; then
        MISSING="${MISSING} ${port}"
    fi
done
if [ -n "$MISSING" ]; then
    echo "[configure-samba] NOTE: ports not listening:${MISSING}"
    echo "[configure-samba] These ports will show as 'closed' or 'filtered' in nmap."
fi

# ── Reload Samba ───────────────────────────────────────────────────
echo "[configure-samba] Reloading Samba configuration..."
if command -v smbcontrol >/dev/null 2>&1; then
    smbcontrol all reload-config 2>/dev/null && \
        echo "  + smbcontrol reload-config OK" || \
        echo "  + smbcontrol reload-config failed (changes take effect on restart)"
fi

echo "[configure-samba] Done."
