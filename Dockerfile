FROM golang:1.16-alpine

ENV APP_NAME server

#RUN apt-get update
RUN apk add --no-cache libpcap-dev gcc libc-dev openssl
#RUN apt-get -y install libpcap-dev
#
#RUN go get github.com/google/gopacket/pcap
#RUN go get github.com/bradleyfalzon/tlsx
#RUN go get github.com/google/gopacket
#RUN go get github.com/google/gopacket/layers
#RUN go get github.com/google/gopacket/pcap
#RUN go get github.com/caddyserver/certmagic
#
#RUN mkdir -p /root/hellos &&\
#	mkdir -p /go/src/${APP_NAME}/certs &&\
#	chmod -R 777 /go/src/${APP_NAME} &&\
#	chmod -R 777 /root/hellos
#COPY ./src/server.go /go/src/${APP_NAME}
#COPY ./src/myblah.go /go/src/${APP_NAME}
#WORKDIR /go/src/${APP_NAME}

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

COPY src /src
WORKDIR /src

RUN go mod init http-server && go mod tidy && go install .
#RUN go build -o ${APP_NAME}
#CMD ./${APP_NAME}

EXPOSE 80
EXPOSE 443
