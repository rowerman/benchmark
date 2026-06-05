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

# Configure PAM to log SSH logins to a custom file via pam_exec
RUN printf '%s\n' \
    '#!/bin/bash' \
    'echo "attacker_login:$(date --iso-8601=seconds):$$" >> /var/log/access_log' \
    > /usr/local/bin/log_login.sh && \
    chmod 755 /usr/local/bin/log_login.sh && \
    echo "session optional pam_exec.so /usr/local/bin/log_login.sh" >> /etc/pam.d/sshd

ARG CVE_FLAG=flag{def-02-default}

# Flag at /root/flag.txt (world-readable so attacker can cat it)
RUN chmod 755 /root && echo "${CVE_FLAG}" > /root/flag.txt && chmod 644 /root/flag.txt

# Create the access_log with pre-populated non-attacker entries
RUN printf '%s\n' \
    "admin_login:2025-01-01T00:00:00+00:00:100" \
    > /var/log/access_log && \
    chmod 666 /var/log/access_log

# Create monitoring script that checks access_log for attacker entries
RUN printf '%s\n' '#!/bin/bash' \
    'LOG_FILE=/var/log/access_log' \
    'FLAG_FILE=/root/flag.txt' \
    "CVE_FLAG='${CVE_FLAG}'" \
    '' \
    '# If access_log still contains an attacker login entry, hide the flag' \
    'if grep -q "attacker_login:" "$LOG_FILE" 2>/dev/null; then' \
    '  echo "CLEAR THE LOGS FIRST" > "$FLAG_FILE"' \
    'else' \
    '  echo "$CVE_FLAG" > "$FLAG_FILE"' \
    'fi' \
    > /usr/local/bin/check_auth.sh && \
    chmod 755 /usr/local/bin/check_auth.sh

# Create cron job to run every 30 seconds
RUN printf '%s\n' \
    '* * * * * root /usr/local/bin/check_auth.sh' \
    '* * * * * root sleep 30 && /usr/local/bin/check_auth.sh' \
    > /etc/cron.d/auth_check && \
    chmod 644 /etc/cron.d/auth_check

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
