#! /bin/bash

sudo apt install autoconf automake libtool

#wolfssl installation
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-kyber --enable-dilithium --enable-wolfclu --enable-shared --enable-aesgcm --enable-dtls --enable-dtls13 --enable-tls --enable-tls13 --enable-dtls-frag-ch --enable-keygen --enable-certgen --enable-certreq --enable-opensslall --enable-all --enable-asn --enable-dual-alg-certs --enable-experimental

sudo make && sudo make check
sudo make install
sudo ldconfig
cd ../

#wolfclu installation
git clone https://github.com/wolfSSL/wolfCLU.git
cd wolfCLU
./autogen.sh
./configure
sudo make && sudo make check
sudo make install
sudo ldconfig