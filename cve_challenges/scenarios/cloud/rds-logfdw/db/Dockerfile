FROM postgres:16.6
ARG CVE_FLAG_HOST_READ=flag{cloud-13-host-read}
COPY init.sql /docker-entrypoint-initdb.d/
COPY grover_volume.conf /rdsdbdata/config/grover_volume.conf
RUN sed -i "s|^flag=.*|flag=${CVE_FLAG_HOST_READ}|" /rdsdbdata/config/grover_volume.conf \
    && chmod 644 /rdsdbdata/config/grover_volume.conf
