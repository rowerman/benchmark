#!/bin/bash
set -e

# Start cron
if [ -f /usr/sbin/cron ]; then
    cron 2>/dev/null || true
fi

# Run initial monitor check
/usr/local/bin/lotl_monitor.sh

# Start SSH daemon
exec /usr/sbin/sshd -D -o PermitRootLogin=no -o PasswordAuthentication=yes
