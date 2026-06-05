FROM ubuntu:24.04

ARG CVE_FLAG=flag{net-02-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 600 /root/flag.txt

# Install python3 and dns tools
RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        python3 netcat-openbsd dnsutils iproute2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY exfil.py /exfil.py
RUN chmod +x /exfil.py

CMD ["python3", "/exfil.py"]
