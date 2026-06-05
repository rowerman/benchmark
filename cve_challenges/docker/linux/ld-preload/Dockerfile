FROM ubuntu:24.04

# Install SSH and build tools (gcc for compiling the evil shared library)
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Allow attacker to run /usr/bin/cat as root with LD_PRELOAD preserved
# Disable use_pty to allow non-interactive sudo over SSH
RUN echo 'Defaults:attacker !use_pty' > /etc/sudoers.d/attacker && \
    echo 'Defaults env_keep += "LD_PRELOAD"' >> /etc/sudoers.d/attacker && \
    echo 'attacker ALL=(ALL) NOPASSWD: /usr/bin/cat' >> /etc/sudoers.d/attacker && \
    chmod 440 /etc/sudoers.d/attacker

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-12-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
