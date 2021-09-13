#!/bin/bash

if [ ! -d "/etc/pki/tls/certs/" ]; then
    mkdir -p "/etc/pki/tls/certs/"
fi
if [ ! -d "/etc/pki/tls/private/" ]; then
    mkdir -p "/etc/pki/tls/private/"
fi
if [ ! -f "/etc/pki/tls/private/exastro-gateway.key" ]; then
    openssl req \
    -new \
    -x509 \
    -sha256 \
    -newkey rsa:2048 \
    -days 3650 \
    -nodes \
    -out /etc/pki/tls/certs/exastro-gateway.pem \
    -keyout /etc/pki/tls/private/exastro-gateway.key \
    -subj "/C=JP/ST=Tokyo/CN=gateway-httpd.exastro-gateway.svc"
fi

httpd -D FOREGROUND
