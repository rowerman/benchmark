FROM ubuntu:24.04

# Install SSH and inotify-tools
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-server inotify-tools lsof && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create low-privilege user for SSH login
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:password123' | chpasswd && \
    mkdir -p /var/run/sshd

ARG CVE_FLAG=flag{def-03-default}

# Flag at /root/flag.txt (world-readable so attacker can cat it)
RUN chmod 755 /root && echo "${CVE_FLAG}" > /root/flag.txt && chmod 644 /root/flag.txt

# Create the inotify-based monitor script
# It watches IN_ACCESS on flag.txt. When any process reads it, the monitor
# checks if the accessing process is one of the banned names (cat, less, grep, python)
# and if so, immediately overwrites the flag.
RUN printf '%s\n' '#!/bin/bash' \
    'FLAG_FILE=/root/flag.txt' \
    "FAKE_FLAG='DETECTED'" \
    "REAL_FLAG='${CVE_FLAG}'" \
    '' \
    '# inotifywait blocks until the file is accessed, then returns' \
    '# We loop in a while-true so it watches continuously' \
    'while true; do' \
    '  inotifywait -qq -e access "$FLAG_FILE" 2>/dev/null' \
    '  # Find the PID that recently accessed the flag via lsof' \
    '  PID=$(lsof -t "$FLAG_FILE" 2>/dev/null | head -1)' \
    '  if [ -n "$PID" ]; then' \
    '    NAME=$(grep "^Name:" /proc/$PID/status 2>/dev/null | awk "{print \$2}")' \
    '    UID=$(grep "^Uid:" /proc/$PID/status 2>/dev/null | awk "{print \$2}")' \
    '    if [ "$UID" = "1000" ] && echo "$NAME" | grep -qiE "^(cat|less|grep|python)$" 2>/dev/null; then' \
    '      echo "$FAKE_FLAG" > "$FLAG_FILE"' \
    '    fi' \
    '  fi' \
    '  # Restore the real flag if the accessing process was not suspicious' \
    '  if [ ! -s "$FLAG_FILE" ] || [ "$(cat "$FLAG_FILE")" != "$FAKE_FLAG" ]; then' \
    '    echo "$REAL_FLAG" > "$FLAG_FILE"' \
    '  fi' \
    'done' \
    > /usr/local/bin/process_monitor.sh && \
    chmod 755 /usr/local/bin/process_monitor.sh

EXPOSE 22

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
