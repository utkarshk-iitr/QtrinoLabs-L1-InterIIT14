#ifndef DTLS_CLIENT_H
#define DTLS_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#include <wolfssl/ssl.h>
#include "liteeth_udp.h"

#define DTLS_CLIENT_LOCAL_PORT      12345
#define DTLS_CLIENT_MAX_MSG_SIZE    4096

#define DTLS_CLIENT_SUCCESS         0
#define DTLS_CLIENT_ERROR          -1
#define DTLS_CLIENT_SSL_ERROR      -2
#define DTLS_CLIENT_CERT_ERROR     -3
#define DTLS_CLIENT_CONNECT_ERROR  -4
#define DTLS_CLIENT_NOT_INIT       -5

typedef struct {
    uint32_t server_ip;
    uint16_t server_port;
    uint16_t local_port;

    const uint8_t  *ca_cert;
    size_t ca_cert_len;

    const uint8_t  *client_cert;
    size_t client_cert_len;

    const uint8_t  *client_key;
    size_t client_key_len;

    int verify_peer;
} dtls_client_config_t;

typedef struct {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    liteeth_udp_ctx_t udp_ctx;
    int connected;
    int initialized;
} dtls_client_t;

int dtls_client_init_system(const uint8_t *mac, uint32_t ip);
void dtls_client_cleanup_system(void);

void dtls_client_config_init(dtls_client_config_t *config);
void dtls_client_config_set_server(dtls_client_config_t *config, uint32_t ip, uint16_t port);
void dtls_client_config_set_ca_cert(dtls_client_config_t *config, const uint8_t *cert, size_t len);

int dtls_client_init(dtls_client_t *client, const dtls_client_config_t *config);
int dtls_client_connect(dtls_client_t *client);
int dtls_client_send(dtls_client_t *client, const uint8_t *data, size_t len);
int dtls_client_recv(dtls_client_t *client, uint8_t *buf, size_t maxlen);

void dtls_client_disconnect(dtls_client_t *client);
void dtls_client_cleanup(dtls_client_t *client);

int dtls_client_get_conn_info(dtls_client_t *client, char *buf, size_t maxlen);

#endif /* DTLS_CLIENT_H */
