#!/bin/bash

PROV="-provider oqsprovider -provider default"

openssl genpkey $PROV -algorithm mldsa65 -out ca_key.pem
openssl req -x509 -new $PROV -key ca_key.pem -out ca_cert.pem -days 30 -subj "/C=IN/O=PQ Root CA/CN=PQCA"

openssl genpkey $PROV -algorithm mldsa65 -out server_key.pem
openssl req -new $PROV -key server_key.pem -out server.csr -subj "/C=IN/O=PQ Server/CN=server.local"
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial $PROV -out server_cert.pem -days 30

rm server.csr ca_key.pem ca_cert.srl

echo "=== Certificates Generated ==="
echo ""

# openssl x509 -in ./server_cert.pem -text -noout | grep -i algo
# openssl x509 -in ./ca_cert.pem -text -noout | grep -i algo