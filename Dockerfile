FROM golang:1.16-alpine

ENV APP_NAME server

RUN apk add --no-cache libpcap-dev gcc libc-dev openssl

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

COPY src /src
WORKDIR /src

RUN go mod init https-server && go mod tidy && go install .
