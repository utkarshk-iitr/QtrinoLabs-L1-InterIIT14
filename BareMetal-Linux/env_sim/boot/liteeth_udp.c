#include <stdio.h>
#include <string.h>
#include "liteeth_udp.h"

#include <generated/csr.h>
#include <generated/soc.h>

#ifdef CSR_ETHMAC_BASE
#include <libliteeth/udp.h>
#include <libliteeth/inet.h>
#endif

static liteeth_udp_ctx_t* g_active_ctx = NULL;  
static int g_eth_initialized = 0;

#ifdef CSR_ETHMAC_BASE
static void udp_rx_callback(uint32_t src_ip, uint16_t src_port, 
                            uint16_t dst_port, void* data, uint32_t length) {

    if (g_active_ctx == NULL) {
        return;
    }
    
    if (src_ip == g_active_ctx->remote_ip && 
        src_port == g_active_ctx->remote_port &&
        dst_port == g_active_ctx->local_port) {
        
        if (length <= LITEETH_RX_BUFFER_SIZE) {
            memcpy(g_active_ctx->rx_buffer, data, length);
            g_active_ctx->rx_data_len = length;
            g_active_ctx->rx_read_pos = 0;
            g_active_ctx->has_pending_data = 1;
        }
    }
}
#endif

int liteeth_init(const uint8_t* mac, uint32_t ip) {

#ifdef CSR_ETHMAC_BASE
    if (g_eth_initialized) {
        return 0;  
    }
    
    printf("[LiteETH] Initializing ethernet...\n");
    eth_init();
    udp_start(mac, ip);
    udp_set_callback(udp_rx_callback);
    g_eth_initialized = 1;
    printf("[LiteETH] Initialized with IP: " IP_FMT "\n", IP_ARGS(ip));
    return 0;
#else
    printf("[LiteETH] Error: Ethernet not available in this build\n");
    return -1;
#endif
}

int liteeth_udp_ctx_init(liteeth_udp_ctx_t* ctx, 
                         uint16_t local_port,
                         uint32_t remote_ip, 
                         uint16_t remote_port) {

    if (ctx == NULL) {
        return -1;
    }
    
    memset(ctx, 0, sizeof(liteeth_udp_ctx_t));
    
    ctx->local_port = local_port;
    ctx->remote_ip = remote_ip;
    ctx->remote_port = remote_port;
    ctx->initialized = 1;
    ctx->has_pending_data = 0;
    ctx->rx_data_len = 0;
    ctx->rx_read_pos = 0;
    
    g_active_ctx = ctx;
    
    printf("[LiteETH] UDP context initialized:\n");
    printf("  Local port: %d\n", local_port);
    printf("  Remote: " IP_FMT ":%d\n", IP_ARGS(remote_ip), remote_port);
    
    return 0;
}

void liteeth_udp_ctx_free(liteeth_udp_ctx_t* ctx) {

    if (ctx == g_active_ctx) {
        g_active_ctx = NULL;
    }
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(liteeth_udp_ctx_t));
    }
}

int liteeth_udp_send(liteeth_udp_ctx_t* ctx, const uint8_t* data, size_t len) {

#ifdef CSR_ETHMAC_BASE
    if (ctx == NULL || !ctx->initialized || data == NULL) {
        printf("[LiteETH] Send: invalid params (ctx=%p, init=%d, data=%p)\n", 
               (void*)ctx, ctx ? ctx->initialized : 0, (void*)data);
        return -1;
    }
    
    if (len > LITEETH_MAX_PACKET_SIZE) {
        printf("[LiteETH] Error: Packet too large (%zu > %d)\n", 
               len, LITEETH_MAX_PACKET_SIZE);
        return -1;
    }
    
    printf("[LiteETH] Sending %zu bytes to " IP_FMT ":%d from port %d\n",
           len, IP_ARGS(ctx->remote_ip), ctx->remote_port, ctx->local_port);
    
    printf("[LiteETH] Resolving ARP for " IP_FMT "...\n", IP_ARGS(ctx->remote_ip));
    if (!udp_arp_resolve(ctx->remote_ip)) {
        printf("[LiteETH] ARP resolution failed for " IP_FMT "\n", 
               IP_ARGS(ctx->remote_ip));
        return -1;
    }
    printf("[LiteETH] ARP resolved successfully\n");
    
    void* tx_buf = udp_get_tx_buffer();
    if (tx_buf == NULL) {
        printf("[LiteETH] Failed to get TX buffer\n");
        return -1;
    }
    memcpy(tx_buf, data, len);
    printf("[LiteETH] Copied %zu bytes to TX buffer\n", len);
    
    printf("[LiteETH] Calling udp_send(local=%d, remote=%d, len=%zu)\n",
           ctx->local_port, ctx->remote_port, len);
    int ret = udp_send(ctx->local_port, ctx->remote_port, len);
    printf("[LiteETH] udp_send returned %d\n", ret);
    
    if (ret == 0) {
        printf("[LiteETH] Send failed (ret=0)\n");
        return -1;
    }
    
    printf("[LiteETH] Successfully sent %zu bytes\n", len);
    return (int)len;
#else
    (void)ctx;
    (void)data;
    (void)len;
    return -1;
#endif
}

int liteeth_udp_recv(liteeth_udp_ctx_t* ctx, uint8_t* buf, size_t len, uint32_t timeout_ms) {

#ifdef CSR_ETHMAC_BASE
    if (ctx == NULL || !ctx->initialized || buf == NULL) {
        return -1;
    }
    
    
    uint32_t elapsed = 0;
    const uint32_t poll_interval = 1;  
    
    while (elapsed < timeout_ms || timeout_ms == 0) {
        
        liteeth_service();
        if (ctx->has_pending_data && ctx->rx_data_len > ctx->rx_read_pos) {
            size_t available = ctx->rx_data_len - ctx->rx_read_pos;
            size_t to_copy = (len < available) ? len : available;
            
            memcpy(buf, ctx->rx_buffer + ctx->rx_read_pos, to_copy);
            ctx->rx_read_pos += to_copy;
            
            if (ctx->rx_read_pos >= ctx->rx_data_len) {
                ctx->has_pending_data = 0;
                ctx->rx_data_len = 0;
                ctx->rx_read_pos = 0;
            }
            
            return (int)to_copy;
        }
        
        if (timeout_ms == 0) {
            return 0;  
        }
        
        
        for (volatile int i = 0; i < 10000; i++) {}
        elapsed += poll_interval;
    }
    
    return 0;  
#else
    (void)ctx;
    (void)buf;
    (void)len;
    (void)timeout_ms;
    return -1;
#endif
}

int liteeth_udp_data_available(liteeth_udp_ctx_t* ctx) {

    if (ctx == NULL || !ctx->initialized) {
        return 0;
    }
    
    liteeth_service();
    return ctx->has_pending_data;
}
void liteeth_service(void) {

#ifdef CSR_ETHMAC_BASE
    if (g_eth_initialized) {
        udp_service();
    }
#endif
}

int liteeth_arp_resolve(uint32_t ip) {

#ifdef CSR_ETHMAC_BASE
    return udp_arp_resolve(ip);
#else
    (void)ip;
    return 0;
#endif
}
