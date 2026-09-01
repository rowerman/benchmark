FROM postgres:16.6
ARG CVE_FLAG=flag{cloud-14-host-rce}
COPY init.sql /docker-entrypoint-initdb.d/
RUN echo "${CVE_FLAG}" > /host_flag.txt && chmod 644 /host_flag.txt
