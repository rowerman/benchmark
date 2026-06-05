#!/bin/bash
# Start Redis (no auth) + SSH in the same container
redis-server --save "" --appendonly no --daemonize yes --protected-mode no --bind 0.0.0.0
exec /usr/sbin/sshd -D -o "PermitRootLogin=no" -o "PasswordAuthentication=yes"
