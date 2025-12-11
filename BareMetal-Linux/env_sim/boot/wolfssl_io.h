#ifndef WOLFSSL_IO_H
#define WOLFSSL_IO_H

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/ssl.h>
#include "liteeth_udp.h"


int wolfssl_io_register_callbacks(WOLFSSL_CTX* ctx);
int wolfssl_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int wolfssl_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
void wolfssl_io_set_udp_ctx(WOLFSSL* ssl, liteeth_udp_ctx_t* udp_ctx);

liteeth_udp_ctx_t* wolfssl_io_get_udp_ctx(WOLFSSL* ssl);

void wolfssl_io_set_timeout(uint32_t timeout_ms);
uint32_t wolfssl_io_get_timeout(void);
void wolfssl_io_set_debug(int enable);

#endif 
