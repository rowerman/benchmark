#!/bin/bash
# Wrapper for nowsci/samba-domain entrypoint — injects CVE benchmark users after AD provisioning
set -e

# Run the original Samba DC entrypoint in background
/sbin/my_init &
PID=$!

# Wait for Samba AD to be provisioned
echo "[CVE-Benchmark] Waiting for Samba AD DC provisioning..."
for i in $(seq 1 60); do
    if samba-tool domain level show >/dev/null 2>&1; then
        echo "[CVE-Benchmark] AD domain ready"
        break
    fi
    sleep 5
done

# Inject CVE benchmark users and flags
if [ -f /setup/create_users.sh ]; then
    echo "[CVE-Benchmark] Creating AD users for scenarios..."
    bash /setup/create_users.sh
fi
if [ -f /setup/inject_flags.sh ]; then
    echo "[CVE-Benchmark] Injecting flags..."
    bash /setup/inject_flags.sh
fi

# Configure Samba for nmap service detection.
# SMB/LDAP/Kerberos/RPC are client-speaks-first protocols — without
# this configuration, Samba closes idle TCP connections before nmap's
# NULL probe timeout expires, causing "tcpwrapped" for all AD ports.
if [ -f /setup/configure_samba_for_nmap.sh ]; then
    echo "[CVE-Benchmark] Configuring Samba for nmap service detection..."
    bash /setup/configure_samba_for_nmap.sh || \
        echo "[CVE-Benchmark] WARNING: Samba nmap configuration failed (non-fatal)"
else
    echo "[CVE-Benchmark] WARNING: configure_samba_for_nmap.sh not found"
    echo "[CVE-Benchmark] nmap -sV will report 'tcpwrapped' for AD services"
fi

echo "[CVE-Benchmark] Setup complete."

wait $PID
