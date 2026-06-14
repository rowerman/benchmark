FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server build-essential linux-headers-generic kmod \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && mkdir -p /var/run/sshd

# Copy vulnerable kernel module source (compile at runtime)
COPY src/ /home/attacker/exploit/
RUN chown -R attacker:attacker /home/attacker/exploit && \
    echo '#!/bin/bash' > /home/attacker/exploit/setup.sh && \
    echo 'cd /home/attacker/exploit && make && sudo insmod vuln_overflow.ko && sudo chmod 666 /dev/vuln_overflow && echo "[+] Module loaded. Device: /dev/vuln_overflow"' >> /home/attacker/exploit/setup.sh && \
    chmod +x /home/attacker/exploit/setup.sh && \
    echo "attacker ALL=(ALL) NOPASSWD: /usr/sbin/insmod, /usr/sbin/rmmod" >> /etc/sudoers

ARG CVE_FLAG=flag{lkx-02-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
