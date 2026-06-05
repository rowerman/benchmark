FROM alpine:latest

RUN apk add --no-cache curl

COPY client.sh /client.sh
RUN chmod +x /client.sh

CMD ["/bin/sh", "/client.sh"]
