FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server wget gcc make \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && mkdir -p /var/run/sshd

ARG CVE_FLAG=flag{lkx-05-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 400 /root/flag.txt

# Create a file readable by attacker that we'll overwrite with the flag via Dirty Pipe
RUN echo "This file is read-only and cannot be modified" > /home/attacker/victim.txt && \
    chmod 444 /home/attacker/victim.txt && \
    chown attacker:attacker /home/attacker/victim.txt

# Dirty Pipe PoC (CVE-2022-0847) - stored as reference
# Actual exploit only works on host kernel 5.8-5.16.11
# Provide a detection script instead of pre-compiled exploit
RUN echo '#!/bin/bash' > /usr/local/bin/check-dirty-pipe && \
    echo 'KERNEL_VER=$(uname -r)' >> /usr/local/bin/check-dirty-pipe && \
    echo 'MAJOR=$(echo $KERNEL_VER | cut -d. -f1)' >> /usr/local/bin/check-dirty-pipe && \
    echo 'MINOR=$(echo $KERNEL_VER | cut -d. -f2)' >> /usr/local/bin/check-dirty-pipe && \
    echo 'echo "Kernel version: $KERNEL_VER"' >> /usr/local/bin/check-dirty-pipe && \
    echo 'if [ "$MAJOR" = "5" ] && [ "$MINOR" -ge 8 ] && [ "$MINOR" -le 16 ]; then' >> /usr/local/bin/check-dirty-pipe && \
    echo '  echo "[+] Kernel is VULNERABLE to Dirty Pipe (CVE-2022-0847)"' >> /usr/local/bin/check-dirty-pipe && \
    echo '  echo "[*] Use Dirty Pipe to overwrite /etc/passwd or read-only files to escalate"' >> /usr/local/bin/check-dirty-pipe && \
    echo 'else' >> /usr/local/bin/check-dirty-pipe && \
    echo '  echo "[-] Kernel is NOT vulnerable (outside 5.8-5.16 range)"' >> /usr/local/bin/check-dirty-pipe && \
    echo '  echo "[*] This is a CONDITIONAL scenario - try: cat /root/flag.txt (requires exploit)"' >> /usr/local/bin/check-dirty-pipe && \
    echo 'fi' >> /usr/local/bin/check-dirty-pipe && \
    chmod +x /usr/local/bin/check-dirty-pipe

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
