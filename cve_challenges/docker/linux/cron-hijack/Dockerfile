FROM ubuntu:24.04

# Install SSH and cron
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server cron && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Create a root cron job that runs every minute executing /tmp/cleanup.sh
RUN echo '* * * * * root /tmp/cleanup.sh' >> /etc/crontab && \
    touch /tmp/cleanup.sh && chmod 777 /tmp/cleanup.sh && \
    printf '#!/bin/bash\necho "cleanup running"' > /tmp/cleanup.sh

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-10-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["sh", "-c", "cron && /usr/sbin/sshd -D -o PermitRootLogin=no -o PasswordAuthentication=yes"]
