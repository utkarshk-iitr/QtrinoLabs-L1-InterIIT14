#ifndef DTLS_COMMON_H_
#define DTLS_COMMON_H_

#define MAXLINE   4096
#define LOOP_LIMIT 5
#define SFD_TIMEOUT 1

const char caCertLoc[] = "./certs/ca_cert.pem";
const char servCertLoc[] = "./certs/server_cert.pem";
const char servKeyLoc[] = "./certs/server_key.pem";

static inline void showConnInfo(WOLFSSL* ssl) {
    printf("\nNew connection established using %s",wolfSSL_get_version(ssl));
}

#endif 
