FROM alpine:3.19

RUN apk add --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing/ --no-cache hashcat

VOLUME /data
WORKDIR /data
USER 10020
ENTRYPOINT ["sh", "-c", "hashcat --brain-server --brain-port $HASHCAT_PORT --brain-password $HASHCAT_PASSWORD"]