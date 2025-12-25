#ifndef WOLFSSL_IO_H
#define WOLFSSL_IO_H

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include "liteeth_udp.h"

#define WOLFSSL_IO_RECV_TIMEOUT_MS 5000
#define WOLFSSL_IO_SEND_TIMEOUT_MS 5000

int wolfssl_io_register_callbacks(WOLFSSL_CTX *ctx);
int wolfssl_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int wolfssl_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int wolfssl_io_set_udp_ctx(WOLFSSL *ssl, liteeth_udp_ctx_t *udp_ctx);

#endif /* WOLFSSL_IO_H */