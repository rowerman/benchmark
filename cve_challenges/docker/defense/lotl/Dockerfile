FROM ubuntu:24.04

# Install SSH, findutils, tar, python3, and cron
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server findutils tar python3 cron && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set SUID bit on find
RUN chmod u+s /usr/bin/find

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

ARG CVE_FLAG=flag{def-05-default}

# Flag at /root/flag.txt (requires SUID find — chmod 600 root-only)
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

# Create monitoring script that detects "find -exec" usage
RUN printf '%s\n' '#!/bin/bash' \
    'FLAG_FILE=/root/flag.txt' \
    "CVE_FLAG='${CVE_FLAG}'" \
    '# Check /proc for find processes with -exec in cmdline' \
    'for pid_dir in /proc/[0-9]*/; do' \
    '  if [ -f "${pid_dir}cmdline" ] && [ -f "${pid_dir}status" ]; then' \
    '    name=$(grep "^Name:" "${pid_dir}status" 2>/dev/null | awk "{print \$2}")' \
    '    if [ "$name" = "find" ]; then' \
    '      cmdline=$(cat "${pid_dir}cmdline" 2>/dev/null | tr "\\0" " ")' \
    '      if echo "$cmdline" | grep -qE -- "-exec[^d]"; then' \
    '        echo "DETECTED" > "$FLAG_FILE"' \
    '        exit 0' \
    '      fi' \
    '    fi' \
    '  fi' \
    'done' \
    '# No suspicious find -exec usage — restore flag' \
    'echo "$CVE_FLAG" > "$FLAG_FILE"' \
    > /usr/local/bin/lotl_monitor.sh && \
    chmod 755 /usr/local/bin/lotl_monitor.sh

# Create cron job to run every 30 seconds
RUN printf '%s\n' \
    '* * * * * root /usr/local/bin/lotl_monitor.sh' \
    '* * * * * root sleep 30 && /usr/local/bin/lotl_monitor.sh' \
    > /etc/cron.d/lotl_check && \
    chmod 644 /etc/cron.d/lotl_check

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
