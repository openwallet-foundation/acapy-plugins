#!/bin/sh
set -eu
apk add --no-cache openssl ca-certificates >/dev/null
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout /certs/webvh.key \
  -out /certs/webvh.crt \
  -subj "/CN=webvh" \
  -addext "subjectAltName=DNS:webvh"
chmod 644 /certs/webvh.crt /certs/webvh.key
cat /etc/ssl/certs/ca-certificates.crt /certs/webvh.crt > /certs/ca-bundle.pem
chmod 644 /certs/ca-bundle.pem
