FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server python3-pip \
    && pip3 install bcc 2>/dev/null || echo "bcc not available via pip - install bpftool from host" \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && mkdir -p /var/run/sshd

# Set up filesystem for reading flag via eBPF
ARG CVE_FLAG=flag{lkx-03-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

# Copy eBPF exploit skeleton
COPY app/ /home/attacker/exploit/
RUN chown -R attacker:attacker /home/attacker/exploit

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
