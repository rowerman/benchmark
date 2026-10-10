FROM postgres:16.6
COPY init.sql /docker-entrypoint-initdb.d/
COPY grover_volume.conf /rdsdbdata/config/grover_volume.conf
RUN chmod 644 /rdsdbdata/config/grover_volume.conf
