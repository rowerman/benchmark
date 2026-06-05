#!/bin/bash
set -e

# Start cron
if [ -f /usr/sbin/cron ]; then
    cron 2>/dev/null || true
fi

# Run initial timestamp check
/usr/local/bin/check_timestamps.sh

# Start SSH daemon
exec /usr/sbin/sshd -D -o PermitRootLogin=no -o PasswordAuthentication=yes
