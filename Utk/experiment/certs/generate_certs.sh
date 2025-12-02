#!/bin/bash
# Generate PQC certificates for OpenSSL with hybrid support

cd "$(dirname "$0")"

# Clean up old certificates
rm -f *.crt *.key *.csr *.srl

# Generate CA key and certificate using RSA (for compatibility) with Dilithium signature
echo "Generating CA certificate with Dilithium..."
openssl req -x509 -new -newkey dilithium3 -keyout ca.key -out ca.crt -nodes -subj "/CN=OQS-CA" -days 365 -config /dev/stdin <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF

# Generate server key using Dilithium
echo "Generating server key..."
openssl genpkey -algorithm dilithium3 -out server.key

# Generate server CSR
echo "Generating server CSR..."
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# Sign server certificate with CA
echo "Signing server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

echo "Certificates generated successfully!"
echo "CA: ca.crt"
echo "Server cert: server.crt"
echo "Server key: server.key"
