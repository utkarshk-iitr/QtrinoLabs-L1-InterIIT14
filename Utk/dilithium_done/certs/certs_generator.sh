#!/bin/bash

PROV="-provider oqsprovider -provider default"

echo "=== Generating PQ Root CA key ==="
openssl genpkey $PROV \
    -algorithm mldsa65 \
    -out ca_key.pem

echo "=== Generating PQ Root CA certificate ==="
openssl req -x509 -new $PROV \
    -key ca_key.pem \
    -out ca_cert.pem \
    -days 3650 \
    -subj "/C=IN/O=PQ Root CA/CN=PQCA"

echo "=== Generating Server key ==="
openssl genpkey $PROV \
    -algorithm mldsa65 \
    -out server_key.pem

echo "=== Generating Server CSR ==="
openssl req -new $PROV \
    -key server_key.pem \
    -out server.csr \
    -subj "/C=IN/O=PQ Server/CN=server.local"

echo "=== Signing Server certificate with CA ==="
openssl x509 -req \
    -in server.csr \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial \
    $PROV \
    -out server_cert.pem \
    -days 825

rm server.csr ca_key.pem ca_cert.srl
echo "=== Done ==="
