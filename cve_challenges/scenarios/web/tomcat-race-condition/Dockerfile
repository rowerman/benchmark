FROM tomcat:9.0.97-jdk11

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable DefaultServlet writes (required for CVE-2024-50379)
RUN sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|' \
    /usr/local/tomcat/conf/web.xml

ARG CVE_FLAG=flag{web-02-default}
RUN echo "${CVE_FLAG}" > /opt/flag.txt && chmod 644 /opt/flag.txt
