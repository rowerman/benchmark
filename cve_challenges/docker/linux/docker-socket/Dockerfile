FROM ubuntu:24.04

# Install SSH and Docker CLI
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server docker.io && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-08-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

# Create a startup script that dynamically creates a group matching
# the host docker socket's GID and adds attacker to it
RUN printf '%s\n' '#!/bin/bash' \
    'set -e' \
    'SOCK_GID=$(stat -c "%g" /var/run/docker.sock 2>/dev/null || true)' \
    'if [ -n "$SOCK_GID" ] && [ "$SOCK_GID" != "0" ]; then' \
    '  if ! getent group "$SOCK_GID" >/dev/null 2>&1; then' \
    '    groupadd -g "$SOCK_GID" hostdocker' \
    '  fi' \
    '  usermod -aG "$SOCK_GID" attacker' \
    'fi' \
    'exec /usr/sbin/sshd -D -o PermitRootLogin=no -o PasswordAuthentication=yes "$@"' \
    > /usr/local/bin/entrypoint.sh && \
    chmod 755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
