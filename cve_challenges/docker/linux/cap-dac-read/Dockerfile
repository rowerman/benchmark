FROM ubuntu:24.04

# Install SSH, build tools, and libcap utilities
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server libcap2-bin gcc libc-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a helper binary that reads /root/flag.txt using CAP_DAC_READ_SEARCH
RUN echo '#include <stdio.h>\n#include <fcntl.h>\n#include <unistd.h>\nint main(){char b[256];int f=open("/root/flag.txt",O_RDONLY);read(f,b,255);printf("%s",b);}' > /tmp/readflag.c && \
    gcc /tmp/readflag.c -o /usr/local/bin/readflag && \
    setcap cap_dac_read_search+ep /usr/local/bin/readflag && \
    chmod 755 /usr/local/bin/readflag

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-09-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
