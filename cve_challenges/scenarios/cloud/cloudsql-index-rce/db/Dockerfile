FROM postgres:16.6
COPY init.sql /docker-entrypoint-initdb.d/
RUN echo "flag{cloud-25-host-rce}" > /host_flag.txt && chmod 644 /host_flag.txt
