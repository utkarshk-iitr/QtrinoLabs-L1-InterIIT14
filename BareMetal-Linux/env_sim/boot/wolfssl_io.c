#include "wolfssl_io.h"

#include <stdio.h>
#include <string.h>

#define WOLFSSL_IO_DEBUG 0

#if WOLFSSL_IO_DEBUG
#define IO_DBG(fmt, ...) printf("[WOLFSSL_IO] " fmt, ##__VA_ARGS__)
#else
#define IO_DBG(fmt, ...)
#endif

int wolfssl_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    liteeth_udp_ctx_t *udp_ctx = (liteeth_udp_ctx_t *)ctx;
    int ret;
    (void)ssl;
    
    if (udp_ctx == NULL) {
        IO_DBG("send_cb: NULL context\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    if (!udp_ctx->connected) {
        IO_DBG("send_cb: Not connected\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    
    IO_DBG("send_cb: Sending %d bytes\n", sz);
    
    #if WOLFSSL_IO_DEBUG
        printf("[WOLFSSL_IO] TX data:\n");
        for (int i = 0; i < sz && i < 64; i++) {
            printf("%02x ", (unsigned char)buf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (sz > 64) printf("... (%d more bytes)\n", sz - 64);
        else printf("\n");
    #endif
    
    ret = liteeth_udp_send(udp_ctx, (const uint8_t *)buf, (size_t)sz);
    
    if (ret < 0) {
        IO_DBG("send_cb: Error %d\n", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    IO_DBG("send_cb: Sent %d bytes\n", ret);

    liteeth_udp_service();
    
    return ret;
}

int wolfssl_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    liteeth_udp_ctx_t *udp_ctx = (liteeth_udp_ctx_t *)ctx;
    int ret;
    (void)ssl;
    
    if (udp_ctx == NULL) {
        IO_DBG("recv_cb: NULL context\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    if (!udp_ctx->connected) {
        IO_DBG("recv_cb: Not connected\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    
    ret = liteeth_udp_recv_nonblock(udp_ctx, (uint8_t *)buf, (size_t)sz);
    if (ret == LITEETH_UDP_WOULD_BLOCK || ret == LITEETH_UDP_QUEUE_EMPTY) {
        liteeth_udp_service();
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    if (ret == LITEETH_UDP_TIMEOUT) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    
    if (ret < 0) {
        IO_DBG("recv_cb: Error %d\n", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    IO_DBG("recv_cb: Received %d bytes\n", ret);
    
    #if WOLFSSL_IO_DEBUG
        printf("[WOLFSSL_IO] RX data:\n");
        for (int i = 0; i < ret && i < 64; i++) {
            printf("%02x ", (unsigned char)buf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (ret > 64) printf("... (%d more bytes)\n", ret - 64);
        else printf("\n");
    #endif
    
    return ret;
}

int wolfssl_io_register_callbacks(WOLFSSL_CTX *ctx) {
    if (ctx == NULL) {
        return -1;
    }
    
    wolfSSL_CTX_SetIORecv(ctx, wolfssl_io_recv);
    wolfSSL_CTX_SetIOSend(ctx, wolfssl_io_send);
    
    IO_DBG("I/O callbacks registered on context\n");
    
    return 0;
}

int wolfssl_io_set_udp_ctx(WOLFSSL *ssl, liteeth_udp_ctx_t *udp_ctx) {
    if (ssl == NULL || udp_ctx == NULL) {
        return -1;
    }
    
    wolfSSL_SetIOReadCtx(ssl, udp_ctx);
    wolfSSL_SetIOWriteCtx(ssl, udp_ctx);
    
    IO_DBG("UDP context set on SSL session\n");
    
    return 0;
}
