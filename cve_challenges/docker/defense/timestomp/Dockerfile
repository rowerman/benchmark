FROM ubuntu:24.04

# Install SSH and tools
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server cron sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

# Give attacker sudo permission to cat only (NOPASSWD)
# Also configure sudo to log to a custom logfile
RUN printf '%s\n' \
    'Defaults logfile=/var/log/sudo.log' \
    'attacker ALL=(ALL) NOPASSWD: /bin/cat' \
    > /etc/sudoers.d/attacker-cat && \
    chmod 440 /etc/sudoers.d/attacker-cat

ARG CVE_FLAG=flag{def-04-default}

# Flag at /root/flag.txt (requires sudo to read)
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

# Set reference timestamp for sudo.log (attacker-owned so touch can restore mtime)
RUN touch -t 202501010000 /var/log/sudo.log && chown attacker:attacker /var/log/sudo.log && \
    stat -c %Y /var/log/sudo.log > /var/log/.sudo_ref_mtime

# Create monitoring script that checks if sudo.log was modified
RUN printf '%s\n' '#!/bin/bash' \
    'FLAG_FILE=/root/flag.txt' \
    "CVE_FLAG='${CVE_FLAG}'" \
    'REF_FILE=/var/log/.sudo_ref_mtime' \
    '# Read the stored reference mtime (set at build time)' \
    'if [ ! -f "$REF_FILE" ]; then' \
    '  stat -c %Y /var/log/sudo.log > "$REF_FILE"' \
    'fi' \
    'REF_MTIME=$(cat "$REF_FILE" 2>/dev/null || echo "0")' \
    'CURRENT_MTIME=$(stat -c %Y /var/log/sudo.log 2>/dev/null || echo "0")' \
    'if [ "$CURRENT_MTIME" != "$REF_MTIME" ]; then' \
    '  echo "DETECTED: TIMESTAMPS MODIFIED" > "$FLAG_FILE"' \
    'else' \
    '  echo "$CVE_FLAG" > "$FLAG_FILE"' \
    'fi' \
    > /usr/local/bin/check_timestamps.sh && \
    chmod 755 /usr/local/bin/check_timestamps.sh

# Create cron job to run every minute
RUN printf '%s\n' \
    '* * * * * root /usr/local/bin/check_timestamps.sh' \
    > /etc/cron.d/timestamp_check && \
    chmod 644 /etc/cron.d/timestamp_check

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
