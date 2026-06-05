FROM ubuntu:24.04

RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server tcpdump ngrep netcat-openbsd python3 iproute2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
