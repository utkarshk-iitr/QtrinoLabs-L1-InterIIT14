#! /bin/bash

git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-kyber --enable-dilithium --enable-shared --enable-aesgcm --enable-dtls --enable-dtls13 --enable-tls --enable-tls13 --enable-dtls-frag-ch --enable-keygen --enable-certgen --enable-certreq --enable-opensslall --enable-all --enable-asn

make -j$(nproc)
sudo make install
sudo ldconfig
