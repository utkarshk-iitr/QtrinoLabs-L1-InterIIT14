
#include <stdio.h>
#include <string.h>
#include "wolfssl_io.h"

static uint32_t g_recv_timeout_ms = 5000;  
static int g_debug_enabled = 1;            

#define IO_DEBUG(fmt, ...) \
    do { if (g_debug_enabled) printf("[WOLFSSL_IO] " fmt "\n", ##__VA_ARGS__); } while(0)

int wolfssl_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    liteeth_udp_ctx_t* udp_ctx = (liteeth_udp_ctx_t*)ctx;
    int ret;
    (void)ssl;  
    if (udp_ctx == NULL) {
        IO_DEBUG("Send error: NULL context");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    if (buf == NULL || sz <= 0) {
        IO_DEBUG("Send error: Invalid buffer (buf=%p, sz=%d)", buf, sz);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    IO_DEBUG("Sending %d bytes...", sz);
    
    ret = liteeth_udp_send(udp_ctx, (const uint8_t*)buf, (size_t)sz);
    
    if (ret < 0) {
        IO_DEBUG("Send failed with error %d", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    IO_DEBUG("Sent %d bytes successfully", ret);
    
    return ret;
}

int wolfssl_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    liteeth_udp_ctx_t* udp_ctx = (liteeth_udp_ctx_t*)ctx;
    int ret;
    (void)ssl;  
    
    if (udp_ctx == NULL) {
        IO_DEBUG("Recv error: NULL context");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    if (buf == NULL || sz <= 0) {
        IO_DEBUG("Recv error: Invalid buffer (buf=%p, sz=%d)", buf, sz);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    IO_DEBUG("Waiting for data (max %d bytes, timeout %u ms)...", sz, g_recv_timeout_ms);
    
    ret = liteeth_udp_recv(udp_ctx, (uint8_t*)buf, (size_t)sz, g_recv_timeout_ms);
    
    if (ret < 0) {
        IO_DEBUG("Recv error: %d", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    
    if (ret == 0) {
        IO_DEBUG("No data available, returning WANT_READ");
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    
    IO_DEBUG("Received %d bytes", ret);
    return ret;
}

int wolfssl_io_register_callbacks(WOLFSSL_CTX* ctx) {
    if (ctx == NULL) {
        IO_DEBUG("Error: NULL wolfSSL context");
        return -1;
    }
    
    wolfSSL_CTX_SetIOSend(ctx, wolfssl_io_send);
    wolfSSL_CTX_SetIORecv(ctx, wolfssl_io_recv);
    
    IO_DEBUG("Custom IO callbacks registered");
    
    return 0;
}

void wolfssl_io_set_udp_ctx(WOLFSSL* ssl, liteeth_udp_ctx_t* udp_ctx) {
    if (ssl != NULL) {
        wolfSSL_SetIOReadCtx(ssl, udp_ctx);
        wolfSSL_SetIOWriteCtx(ssl, udp_ctx);
        IO_DEBUG("UDP context set for SSL session");
    }
}

liteeth_udp_ctx_t* wolfssl_io_get_udp_ctx(WOLFSSL* ssl) {
    if (ssl == NULL) {
        return NULL;
    }
    
    return (liteeth_udp_ctx_t*)wolfSSL_GetIOReadCtx(ssl);
}

void wolfssl_io_set_timeout(uint32_t timeout_ms) {
    g_recv_timeout_ms = timeout_ms;
    IO_DEBUG("Receive timeout set to %u ms", timeout_ms);
}

uint32_t wolfssl_io_get_timeout(void) {
    return g_recv_timeout_ms;
}

void wolfssl_io_set_debug(int enable) {
    g_debug_enabled = enable;
}
