FROM ubuntu:24.04

# Install build deps and SSH, then compile vulnerable sudo from source
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server wget ca-certificates \
        build-essential libpam0g-dev libselinux1-dev libaudit-dev libssl-dev flex bison && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Build and install vulnerable sudo 1.9.16p2 from source (CVE-2025-32463)
RUN set -ex; \
    cd /tmp; \
    wget -q "https://www.sudo.ws/dist/sudo-1.9.16p2.tar.gz"; \
    tar xzf sudo-1.9.16p2.tar.gz; \
    cd sudo-1.9.16p2; \
    ./configure --prefix=/usr --libexecdir=/usr/lib --with-all-insults --with-pam \
        --with-env-editor --with-passprompt="[sudo] password for %p: " \
        --without-lecture --with-tty-tickets --disable-root-mailer; \
    make -j$(nproc); \
    make install; \
    cd /; rm -rf /tmp/sudo-1.9.16p2*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-05-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
