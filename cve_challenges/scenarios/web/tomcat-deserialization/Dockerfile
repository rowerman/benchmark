FROM tomcat:9.0.98-jdk11

# Install curl for potential downloads
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable DefaultServlet writes (required for CVE-2025-24813)
RUN sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|' \
    /usr/local/tomcat/conf/web.xml

# Add commons-collections 3.2.1 as deserialization gadget
RUN curl -sfSL "https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar" \
    -o /usr/local/tomcat/lib/commons-collections-3.2.1.jar

# Configure file-based session persistence (required for exploit)
RUN sed -i '/<\/Context>/i \
<Manager className="org.apache.catalina.session.PersistentManager" saveOnRestart="true">\
  <Store className="org.apache.catalina.session.FileStore"/>\
</Manager>' /usr/local/tomcat/conf/context.xml

# Create session storage directory with write permissions
RUN mkdir -p /usr/local/tomcat/work/Catalina/localhost/ROOT && chmod 777 /usr/local/tomcat/work/Catalina/localhost/ROOT

ARG CVE_FLAG=flag{web-01-default}
RUN echo "${CVE_FLAG}" > /opt/flag.txt && chmod 644 /opt/flag.txt
