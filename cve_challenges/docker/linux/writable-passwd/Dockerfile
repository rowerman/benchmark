FROM ubuntu:24.04

# Install SSH
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Make /etc/passwd world-writable (misconfiguration)
RUN chmod 646 /etc/passwd

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-13-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
