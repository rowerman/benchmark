#!/bin/bash
set -e

# Start the inotify process monitor in background
/usr/local/bin/process_monitor.sh &

# Start SSH daemon
exec /usr/sbin/sshd -D -o PermitRootLogin=no -o PasswordAuthentication=yes
