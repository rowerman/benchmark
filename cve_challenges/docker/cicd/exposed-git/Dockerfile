FROM nginx:alpine
COPY html/ /usr/share/nginx/html/
ARG CVE_FLAG=flag{ci-02-default}
RUN apk add --no-cache git && \
    cd /usr/share/nginx/html && \
    git init && \
    git config user.email "admin@corp.com" && \
    git config user.name "Admin" && \
    git add index.html && \
    git commit -m "Initial commit: corporate dashboard" && \
    echo "${CVE_FLAG}" > flag.txt && \
    git add flag.txt && \
    git commit -m "Add deployment credentials" && \
    rm flag.txt && \
    git add -A && \
    git commit -m "Remove sensitive file" && \
    echo "Exposed .git configured"
