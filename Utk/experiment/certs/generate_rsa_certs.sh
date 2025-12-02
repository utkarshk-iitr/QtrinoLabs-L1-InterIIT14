#!/bin/bash
# Generate RSA certificates for TLS (authentication)
# We'll use Kyber/ML-KEM for key exchange during handshake

cd "$(dirname "$0")"

echo "Cleaning old certificates..."
rm -f *.crt *.key *.csr *.srl

echo "Generating CA key and certificate (RSA)..."
openssl req -x509 -new -newkey rsa:2048 -keyout ca.key -out ca.crt -nodes \
    -subj "/CN=PQC-Test-CA" -days 365

echo "Generating server key (RSA)..."
openssl genrsa -out server.key 2048

echo "Generating server CSR..."
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

echo "Signing server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365

echo ""
echo "✓ Certificates generated successfully!"
echo "  CA cert: ca.crt"
echo "  Server cert: server.crt"
echo "  Server key: server.key"
echo ""
echo "Note: These are RSA certificates for authentication."
echo "PQC key exchange (Kyber/ML-KEM) will be used during TLS handshake!"
