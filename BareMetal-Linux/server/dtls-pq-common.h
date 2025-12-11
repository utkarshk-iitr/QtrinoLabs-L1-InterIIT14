#ifndef DTLS_PQ_COMMON_H_
#define DTLS_PQ_COMMON_H_

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#define MAXLINE   4096
#define SERV_PORT 23456

const char caCertLoc[] = "certs/mldsa44_root_cert.pem";
const char servCertLoc[] = "certs/mldsa44_entity_cert.pem";
const char servKeyLoc[] = "certs/mldsa44_entity_key.pem";

static inline void showConnInfo(WOLFSSL* ssl) {
    printf("New connection established using %s %s\n",
            wolfSSL_get_version(ssl), wolfSSL_get_cipher(ssl));
}

#endif
