FROM python:3.11-slim

WORKDIR /waf

# Copy DARWIN's WAF server
COPY benchmarks/local_waf/waf_server.py /waf/waf_server.py

# Wrapper to override backend host (original server hardcoded localhost)
RUN printf '#!/bin/sh\nsed -i "s|http://localhost:|http://${BACKEND_HOST:-localhost}:|" /waf/waf_server.py\nexec python3 /waf/waf_server.py 8080 ${BACKEND_PORT:-80}\n' > /waf/start.sh && chmod +x /waf/start.sh

ENV BACKEND_HOST=localhost
ENV BACKEND_PORT=80

EXPOSE 8080
CMD ["/waf/start.sh"]
