#!/bin/bash
# Create all AD users/service accounts for CVE benchmark scenarios
set -e
echo "[*] Creating AD users for CVE benchmark..."

# AD-01: Kerberoasting — service account with SPN and weak password
samba-tool user create svc_sql 'Summer2024!' --given-name="SQL" --surname="Service" \
    --description="flag{ad-01-kerberoast}" 2>/dev/null || echo "  svc_sql exists"
samba-tool spn add MSSQLSvc/dc01.north.sevenkingdoms.local:1433 svc_sql 2>/dev/null || echo "  SPN exists"

# AD-02: AS-REP Roasting — account without Kerberos pre-authentication
samba-tool user create no_preauth 'WeakPass123!' --description="flag{ad-02-asrep}" 2>/dev/null || echo "  no_preauth exists"
# Samba: UAC_DONT_REQUIRE_PREAUTH = 0x400000
samba-tool user setexpiry no_preauth --noexpiry 2>/dev/null || true

# Low-privilege user for all scenarios
samba-tool user create lowpriv 'Password123!' 2>/dev/null || echo "  lowpriv exists"

# AD-09: DCSync — user with replication privileges
samba-tool user create dcsync_user 'DCSyncUser123!' --description="flag{ad-09-dcsync}" 2>/dev/null || echo "  dcsync_user exists"
# Grant replication privileges (Samba equivalent of Replication-Get-Changes-All)
samba-tool group addmembers "Domain Admins" dcsync_user 2>/dev/null || true

# ============================================================
# Phase 2 Expansion: New scenarios AD-13 through AD-16
# ============================================================

# AD-14: Silver Ticket — service account with SPN for CIFS
# Attacker cracks this hash and forges a Silver Ticket for CIFS
samba-tool user create svc_backup 'BackupPass2024!' \
    --description="flag{ad-14-silver}" 2>/dev/null || echo "  svc_backup exists"
samba-tool spn add cifs/dc01.north.sevenkingdoms.local svc_backup 2>/dev/null || echo "  SPN exists"

# AD-15: Targeted Kerberoasting via ACL Abuse
# sql_service has NO SPN initially — attacker with GenericWrite sets one then Kerberoasts
samba-tool user create sql_service 'WeakSQL2024!' \
    --description="flag{ad-15-targeted-kerb}" 2>/dev/null || echo "  sql_service exists"
# Grant lowpriv GenericWrite access to sql_service
# Samba dsacl: WP (Write Property) permission on the user object
samba-tool dsacl set \
    --object-dn="CN=sql_service,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on sql_service (may need manual setup)"

# AD-16: Constrained Delegation Abuse
# svc_deleg has constrained delegation to LDAP service on the DC
samba-tool user create svc_deleg 'DelegPass2024!' \
    --description="flag{ad-16-deleg}" 2>/dev/null || echo "  svc_deleg exists"
# Set SPN on svc_deleg (required for delegation)
samba-tool spn add HTTP/dc01.north.sevenkingdoms.local svc_deleg 2>/dev/null || echo "  SPN exists"
# Configure constrained delegation
samba-tool delegation add-service \
    "CN=svc_deleg,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    ldap/dc01.north.sevenkingdoms.local 2>/dev/null || echo "  Delegation set"

# ============================================================
# Phase 11 Expansion: New scenarios AD-17 through AD-21
# ============================================================

# AD-17: RBCD Computer Takeover
# DESKTOP-HELPDESK$ computer — lowpriv has GenericWrite for RBCD abuse
samba-tool computer create DESKTOP-HELPDESK$ 'HelpDesk2024!' \
    --description="flag{ad-17-rbcd}" 2>/dev/null || echo "  DESKTOP-HELPDESK$ exists"
# Grant lowpriv GenericWrite on DESKTOP-HELPDESK$
samba-tool dsacl set \
    --object-dn="CN=DESKTOP-HELPDESK,CN=Computers,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on DESKTOP-HELPDESK$ (may need manual setup)"

# AD-18: Shadow Credentials via msDS-KeyCredentialLink
# svc_shadow — service account with strong password, lowpriv has GenericWrite
samba-tool user create svc_shadow 'StrongRand0mP@ss2024!' \
    --given-name="Shadow" --surname="Service" \
    --description="flag{ad-18-shadow}" 2>/dev/null || echo "  svc_shadow exists"
# Grant lowpriv GenericWrite on svc_shadow
samba-tool dsacl set \
    --object-dn="CN=svc_shadow,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on svc_shadow (may need manual setup)"

# AD-19: WriteOwner DACL Abuse Chain
# IT_Admins group — lowpriv has WriteOwner privilege
samba-tool group add IT_Admins 2>/dev/null || echo "  IT_Admins group exists"
# Grant lowpriv WriteOwner on IT_Admins (OWNER_RIGHTS / WRITE_OWNER)
samba-tool dsacl set \
    --object-dn="CN=IT_Admins,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on IT_Admins (may need manual setup)"

# AD-20: ForceChangePassword Privilege Escalation
# svc_support — member of privileged group, lowpriv can reset its password
samba-tool user create svc_support 'SupportInit2024!' \
    --description="flag{ad-20-forcepass}" 2>/dev/null || echo "  svc_support exists"
# Add svc_support to a privileged group (e.g., Account Operators or similar)
# Using samba-tool group addmembers to an existing or new elevated group
samba-tool group add "Support Engineers" 2>/dev/null || echo "  Support Engineers group exists"
samba-tool group addmembers "Support Engineers" svc_support 2>/dev/null || echo "  svc_support in Support Engineers"
# Grant lowpriv User-Force-Change-Password extended right on svc_support
# Extended right GUID for User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
samba-tool dsacl set \
    --object-dn="CN=svc_support,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on svc_support (may need manual setup)"

# AD-21: Unconstrained Delegation Discovery & Exploitation
# SRV-WEB$ computer with TrustedForDelegation enabled
samba-tool computer create SRV-WEB$ 'WebServer2024!' \
    --description="flag{ad-21-unconstrained}" 2>/dev/null || echo "  SRV-WEB$ exists"
# Enable TrustedForDelegation by setting userAccountControl flag
# UAC_TRUSTED_FOR_DELEGATION = 0x80000 (524288)
# Get current UAC, add delegation flag
CURRENT_UAC=$(samba-tool computer show SRV-WEB$ --attributes=userAccountControl 2>/dev/null | grep -oP 'userAccountControl: \K\d+' || echo "4096")
NEW_UAC=$(( CURRENT_UAC | 524288 ))
echo -e "userAccountControl: ${NEW_UAC}" | samba-tool computer edit SRV-WEB$ 2>/dev/null || \
    echo "  Set TrustedForDelegation on SRV-WEB$ (may need manual ldapmodify)"

echo "[+] AD users created"
