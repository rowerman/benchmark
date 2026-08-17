FROM elasticsearch:8.11.0

ARG CVE_FLAG=flag{db-07-default}
USER root
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
USER elasticsearch
