#!/bin/ash
set -e

openssl ecparam -genkey -name secp384r1 -out /root/server.key
openssl req -new -x509 -sha256 -key /root/server.key -out /root/server.crt -days 3650\
	-subj  "/C=CA/ST=QC/O=Company Inc/CN=example.com"

exec "$@"
