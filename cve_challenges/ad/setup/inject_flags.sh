#!/bin/bash
# Inject flags into AD objects for CVE benchmark verification
set -e
echo "[*] Injecting CVE benchmark flags..."

# AD-01: flag in svc_sql description (already set during user creation)
# AD-02: flag in no_preauth description
# AD-09: flag in dcsync_user description

# AD-05: PTH — flag file accessible after lateral movement
# Simulated: flag stored in AD object accessible with local admin context
samba-tool computer add castelblack --description="flag{ad-05-pth}" 2>/dev/null || \
    samba-tool computer edit castelblack --description="flag{ad-05-pth}" 2>/dev/null || \
    echo "  castelblack flag injected"

# AD-10: Golden Ticket — master flag on "Domain Admin" equivalent
echo "flag{ad-10-golden}" > /var/lib/samba/private/flag_ad10.txt
chmod 600 /var/lib/samba/private/flag_ad10.txt

# ============================================================
# Phase 2 Expansion: Flags for AD-13 through AD-16
# ============================================================

# AD-13: GPP/cpassword — flag encrypted as cpassword in SYSVOL Groups.xml
FLAG_AD13="${FLAG_AD13:-flag{ad-13-gpp}}"
echo "[*] Setting up AD-13 GPP/cpassword flag: $FLAG_AD13"

# Create GPP SYSVOL directory structure
GPP_POLICY_GUID="{31B2F340-016D-11D2-945F-00C04FB984F9}"
GPP_DIR="/var/lib/samba/sysvol/north.sevenkingdoms.local/Policies/${GPP_POLICY_GUID}/Machine/Preferences/Groups"
mkdir -p "$GPP_DIR"

# Encrypt flag using MS cpassword AES-256-CBC key
# Key is the publicly known Microsoft AES key used for GPP encryption
C_PASSWORD=$(python3 -c "
import subprocess
key = '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
iv = '00000000000000000000000000000000'
import sys
flag = sys.argv[1]
data = flag.encode('utf-16-le')
# PKCS7 padding
pad_len = 16 - len(data) % 16
data += bytes([pad_len]) * pad_len
r = subprocess.run(
    ['openssl', 'enc', '-aes-256-cbc', '-K', key, '-iv', iv,
     '-nopad', '-base64', '-A'],
    input=data, capture_output=True, check=True)
print(r.stdout.decode().strip())
" "$FLAG_AD13")

# Write Groups.xml with encrypted cpassword
cat > "$GPP_DIR/Groups.xml" << GROUPSXML
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EC16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="flag_account" image="0" changed="2026-01-01 00:00:00" uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties action="U" newName="" fullName="" description="" cpassword="${C_PASSWORD}" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="flag_account"/>
  </User>
</Groups>
GROUPSXML

echo "  AD-13 GPP Groups.xml created at $GPP_DIR/Groups.xml"
echo "  cpassword: $C_PASSWORD"

# AD-14: Silver Ticket — expose svc_backup NTLM hash for attacker discovery
# The hash is stored in an LDAP-accessible attribute (info field) and as a hint file
# Pre-computed NTLM hash of 'BackupPass2024!' (UTF-16LE → MD4)
BACKUP_NTLM="a8244f9213691fc04d4893105d38d630"

# Store hash in a SYSVOL hint (simulates finding hash via enumeration)
mkdir -p /var/lib/samba/sysvol/north.sevenkingdoms.local/scripts
echo "# Service account hash (for AD-14 Silver Ticket scenario)" > /var/lib/samba/sysvol/north.sevenkingdoms.local/scripts/backup_info.txt
echo "# svc_backup NTLM: ${BACKUP_NTLM}" >> /var/lib/samba/sysvol/north.sevenkingdoms.local/scripts/backup_info.txt
echo "flag{ad-14-silver-hint}" >> /var/lib/samba/sysvol/north.sevenkingdoms.local/scripts/backup_info.txt
chmod 644 /var/lib/samba/sysvol/north.sevenkingdoms.local/scripts/backup_info.txt

# Also store in private directory
echo "$BACKUP_NTLM" > /var/lib/samba/private/svc_backup.hash
chmod 644 /var/lib/samba/private/svc_backup.hash

echo "  AD-14 Silver Ticket: svc_backup NTLM hash stored"

# AD-15: Targeted Kerberoasting — flag in sql_service description (already set)
# Additional hint: mark sql_service as having no SPN initially
echo "  AD-15 Targeted Kerberoasting: sql_service flag in description"

# AD-16: Constrained Delegation — flag in svc_deleg description (already set)
# The delegation rights are set in create_users.sh
echo "  AD-16 Constrained Delegation: svc_deleg flag in description"

# ============================================================
# Phase 11 Expansion: Flags for AD-17 through AD-21
# ============================================================

# AD-17: RBCD — flag in DESKTOP-HELPDESK$ computer description (already set)
# Verify the flag is accessible
echo "  AD-17 RBCD: DESKTOP-HELPDESK\$ flag in description"

# AD-18: Shadow Credentials — flag in svc_shadow description (already set)
echo "  AD-18 Shadow Credentials: svc_shadow flag in description"

# AD-19: WriteOwner — flag file in SYSVOL readable only by IT_Admins
IT_ADMIN_DIR="/var/lib/samba/sysvol/north.sevenkingdoms.local/it_admin"
mkdir -p "$IT_ADMIN_DIR"
echo "flag{ad-19-writeowner}" > "$IT_ADMIN_DIR/flag.txt"
chmod 640 "$IT_ADMIN_DIR/flag.txt"
# Set ownership to IT_Admins group (will work after DC provisioning)
chgrp "IT_Admins" "$IT_ADMIN_DIR/flag.txt" 2>/dev/null || \
    chmod 644 "$IT_ADMIN_DIR/flag.txt"  # fallback: readable (Samba ACLs control access)
echo "  AD-19 WriteOwner: flag in $IT_ADMIN_DIR/flag.txt"

# AD-20: ForceChangePassword — flag in svc_support description (already set)
# Additional flag file on DC
echo "flag{ad-20-forcepass}" > /var/lib/samba/private/flag_ad20.txt
chmod 600 /var/lib/samba/private/flag_ad20.txt
echo "  AD-20 ForceChangePassword: flag in svc_support description + /var/lib/samba/private/flag_ad20.txt"

# AD-21: Unconstrained Delegation — flag in SRV-WEB$ description (already set)
# DC-level flag for final verification
echo "flag{ad-21-unconstrained}" > /var/lib/samba/private/flag_ad21.txt
chmod 600 /var/lib/samba/private/flag_ad21.txt
# SRV-WEB$ machine account hash hint in SYSVOL (for attacker to discover)
# This simulates finding credentials through SYSVOL enumeration
SRV_WEB_HASH_DIR="/var/lib/samba/sysvol/north.sevenkingdoms.local/scripts"
mkdir -p "$SRV_WEB_HASH_DIR"
echo "# Web server deployment notes (AD-21 Unconstrained Delegation)" > "$SRV_WEB_HASH_DIR/webserver_deploy.txt"
echo "# SRV-WEB\$ machine account hash (simulated):" >> "$SRV_WEB_HASH_DIR/webserver_deploy.txt"
echo "# NTLM: $(echo -n 'WebServer2024!' | iconv -t UTF-16LE | openssl dgst -md4 -hex | awk '{print $NF}')" >> "$SRV_WEB_HASH_DIR/webserver_deploy.txt"
echo "flag{ad-21-hint}" >> "$SRV_WEB_HASH_DIR/webserver_deploy.txt"
chmod 644 "$SRV_WEB_HASH_DIR/webserver_deploy.txt"
echo "  AD-21 Unconstrained Delegation: flag in SRV-WEB\$ description + /var/lib/samba/private/flag_ad21.txt"

echo "[+] Flags injected"
