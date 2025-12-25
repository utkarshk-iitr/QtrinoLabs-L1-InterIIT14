#include "liteeth_udp.h"

#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <generated/mem.h>

#ifdef CSR_ETHMAC_BASE
#include <libliteeth/udp.h>
#include <libliteeth/inet.h>
#endif

#define LITEETH_UDP_DEBUG 0

#if LITEETH_UDP_DEBUG
#define DBG_PRINT(fmt, ...) printf("[LITEETH] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

static int g_initialized = 0;

static liteeth_packet_t rx_queue[LITEETH_UDP_RX_QUEUE_SIZE];
static volatile int rx_queue_head = 0;
static volatile int rx_queue_tail = 0;
static volatile int rx_queue_count_val = 0;


static liteeth_udp_ctx_t *g_active_ctx = NULL;

static int queue_is_full(void) {
    return rx_queue_count_val >= LITEETH_UDP_RX_QUEUE_SIZE;
}

static int queue_is_empty(void) {
    return rx_queue_count_val == 0;
}

static int queue_push(const uint8_t *data, uint32_t len, uint32_t src_ip, uint16_t src_port, uint16_t dst_port) {
    if (queue_is_full()) {
        DBG_PRINT("RX queue full!");
        return LITEETH_UDP_QUEUE_FULL;
    }
    
    if (len > LITEETH_UDP_MAX_PACKET_SIZE) {
        len = LITEETH_UDP_MAX_PACKET_SIZE;
    }
    
    liteeth_packet_t *pkt = &rx_queue[rx_queue_head];
    memcpy(pkt->data, data, len);
    pkt->len = len;
    pkt->src_ip = src_ip;
    pkt->src_port = src_port;
    pkt->dst_port = dst_port;
    pkt->valid = 1;
    
    rx_queue_head = (rx_queue_head + 1) % LITEETH_UDP_RX_QUEUE_SIZE;
    rx_queue_count_val++;
    
    DBG_PRINT("Queued packet: %lu bytes from " IP_FMT ":%u (queue=%d)\n",
              (unsigned long)len, IP_ARGS(src_ip), src_port, rx_queue_count_val);
    
    return LITEETH_UDP_SUCCESS;
}

static int queue_pop(uint8_t *buf, size_t maxlen, uint32_t *src_ip,
                     uint16_t *src_port, uint16_t *dst_port) {
    if (queue_is_empty()) {
        return LITEETH_UDP_QUEUE_EMPTY;
    }
    
    liteeth_packet_t *pkt = &rx_queue[rx_queue_tail];
    
    size_t copy_len = (pkt->len < maxlen) ? pkt->len : maxlen;
    memcpy(buf, pkt->data, copy_len);
    
    if (src_ip) *src_ip = pkt->src_ip;
    if (src_port) *src_port = pkt->src_port;
    if (dst_port) *dst_port = pkt->dst_port;
    
    pkt->valid = 0;
    rx_queue_tail = (rx_queue_tail + 1) % LITEETH_UDP_RX_QUEUE_SIZE;
    rx_queue_count_val--;
    
    DBG_PRINT("Dequeued packet: %u bytes (queue=%d)\n", 
              (unsigned)copy_len, rx_queue_count_val);
    
    return (int)copy_len;
}

static void udp_rx_callback(uint32_t src_ip, uint16_t src_port, uint16_t dst_port, void *data, uint32_t length) {
    DBG_PRINT("RX callback: %lu bytes from " IP_FMT ":%u to port %u\n",
              (unsigned long)length, IP_ARGS(src_ip), (unsigned)src_port, (unsigned)dst_port);

    if (g_active_ctx != NULL) {
        DBG_PRINT("Filter: expecting from " IP_FMT ":%u to port %u\n",
                  IP_ARGS(g_active_ctx->remote_ip),
                  (unsigned)g_active_ctx->remote_port,
                  (unsigned)g_active_ctx->local_port);

        if (g_active_ctx->remote_ip != 0 && src_ip != g_active_ctx->remote_ip) {
            DBG_PRINT("Dropping packet: IP mismatch (got " IP_FMT ", expected " IP_FMT ")\n",
                      IP_ARGS(src_ip), IP_ARGS(g_active_ctx->remote_ip));
            return;
        }
        if (g_active_ctx->remote_port != 0 && src_port != g_active_ctx->remote_port) {
            DBG_PRINT("Dropping packet: src port mismatch (got %u, expected %u)\n",
                      (unsigned)src_port, (unsigned)g_active_ctx->remote_port);
            return;
        }
        if (dst_port != g_active_ctx->local_port) {
            DBG_PRINT("Dropping packet: dst port mismatch (got %u, expected %u)\n",
                      (unsigned)dst_port, (unsigned)g_active_ctx->local_port);
            return;
        }
        DBG_PRINT("Packet passed filter\n");
    }

    int ret = queue_push((const uint8_t *)data, length, src_ip, src_port, dst_port);
    DBG_PRINT("queue_push returned %d, queue count=%d\n", ret, rx_queue_count_val);
    (void)ret;
}

int liteeth_init(const uint8_t *mac, uint32_t ip) {
    if (g_initialized) {
        return LITEETH_UDP_SUCCESS;
    }
    
        DBG_PRINT("Initializing UDP layer\n");
        DBG_PRINT("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        DBG_PRINT("IP: " IP_FMT "\n", IP_ARGS(ip));
    
    eth_init();
    udp_start(mac, ip);
    
    DBG_PRINT("Setting UDP callback...\n");
    udp_set_callback(udp_rx_callback);
    DBG_PRINT("UDP callback set\n");
    
    memset(rx_queue, 0, sizeof(rx_queue));
    rx_queue_head = 0;
    rx_queue_tail = 0;
    rx_queue_count_val = 0;
    
    g_active_ctx = NULL;
    g_initialized = 1;
    
    DBG_PRINT("UDP layer initialized\n");
    
    return LITEETH_UDP_SUCCESS;
}

void liteeth_udp_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    udp_set_callback(NULL);
    liteeth_udp_rx_queue_clear();
    
    g_active_ctx = NULL;
    g_initialized = 0;
    
    DBG_PRINT("UDP layer cleaned up\n");
}

int liteeth_udp_connect(liteeth_udp_ctx_t *ctx, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port) {
    if (!g_initialized) {
        return LITEETH_UDP_NOT_INIT;
    }
    
    if (ctx == NULL) {
        return LITEETH_UDP_ERROR;
    }
    
    liteeth_udp_rx_queue_clear();
    DBG_PRINT("Resolving ARP for " IP_FMT "...\n", IP_ARGS(remote_ip));
    if (!udp_arp_resolve(remote_ip)) {
        DBG_PRINT("ARP resolution failed\n");
        return LITEETH_UDP_ARP_FAILED;
    }
    DBG_PRINT("ARP resolved\n");
    
    ctx->local_ip = udp_get_ip();
    ctx->remote_ip = remote_ip;
    ctx->local_port = local_port;
    ctx->remote_port = remote_port;
    ctx->initialized = 1;
    ctx->connected = 1;
    
    g_active_ctx = ctx;
    
    DBG_PRINT("Connected: local port %u -> " IP_FMT ":%u\n",
              local_port, IP_ARGS(remote_ip), remote_port);
    
    return LITEETH_UDP_SUCCESS;
}

void liteeth_udp_close(liteeth_udp_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    
    if (g_active_ctx == ctx) {
        g_active_ctx = NULL;
    }
    
    ctx->connected = 0;
    ctx->initialized = 0;
    
    liteeth_udp_rx_queue_clear();
    
    DBG_PRINT("Connection closed\n");
}

int liteeth_udp_send(liteeth_udp_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!g_initialized) {
        return LITEETH_UDP_NOT_INIT;
    }
    
    if (ctx == NULL || !ctx->connected) {
        return LITEETH_UDP_ERROR;
    }
    
    if (len > LITEETH_UDP_MAX_PACKET_SIZE) {
        printf("[LITEETH] Warning: packet too large (%u), truncating\n", (unsigned)len);
        len = LITEETH_UDP_MAX_PACKET_SIZE;
    }
    
    void *tx_buf = udp_get_tx_buffer();
    memcpy(tx_buf, data, len);
    
    DBG_PRINT("Sending %u bytes to " IP_FMT ":%u\n", (unsigned)len, IP_ARGS(ctx->remote_ip), ctx->remote_port);
    
    int ret = udp_send(ctx->local_port, ctx->remote_port, (uint32_t)len);
    
    if (ret == 0) {
        printf("[LITEETH] Send failed (ARP not resolved?)\n");
        return LITEETH_UDP_ERROR;
    }
    
    return (int)len;
}

int liteeth_udp_recv(liteeth_udp_ctx_t *ctx, uint8_t *buf, size_t maxlen,
                     uint32_t timeout_ms) {
    if (!g_initialized) {
        return LITEETH_UDP_NOT_INIT;
    }
    
    if (ctx == NULL || !ctx->connected) {
        return LITEETH_UDP_ERROR;
    }
    
    DBG_PRINT("recv: waiting for packet (timeout=%lu ms)\n", (unsigned long)timeout_ms);
    
    uint32_t iterations = 0;
    uint32_t max_iterations = 100000000U;
    
    while (iterations < max_iterations) {
        udp_service();
        int ret = queue_pop(buf, maxlen, NULL, NULL, NULL);
        if (ret > 0) {
            DBG_PRINT("recv: got %d bytes after %lu iterations\n", ret, (unsigned long)iterations);
            return ret;
        }
        
        for (volatile int i = 0; i < 10; i++);
        
        iterations++;
        if ((iterations % 100000U) == 0) {
            DBG_PRINT("recv: still waiting... (%lu iterations)\n", (unsigned long)iterations);
        }
    }
    
    DBG_PRINT("recv: timeout after %lu iterations\n", (unsigned long)iterations);
    return LITEETH_UDP_TIMEOUT;
}

int liteeth_udp_recv_nonblock(liteeth_udp_ctx_t *ctx, uint8_t *buf, size_t maxlen) {
    if (!g_initialized) {
        return LITEETH_UDP_NOT_INIT;
    }
    
    if (ctx == NULL || !ctx->connected) {
        return LITEETH_UDP_ERROR;
    }
    
    udp_service();
    
    int ret = queue_pop(buf, maxlen, NULL, NULL, NULL);
    if (ret == LITEETH_UDP_QUEUE_EMPTY) {
        return LITEETH_UDP_WOULD_BLOCK;
    }
    
    return ret;
}

static uint32_t g_service_count = 0;

void liteeth_udp_service(void) {
    if (g_initialized) {
        g_service_count++;
        if ((g_service_count % 50000) == 0) {
            DBG_PRINT("udp_service called %lu times, queue=%d\n",
                      (unsigned long)g_service_count, rx_queue_count_val);
        }
        udp_service();
    }
}

int liteeth_udp_arp_resolve(uint32_t ip) {
    if (!g_initialized) {
        return LITEETH_UDP_NOT_INIT;
    }
    
    if (udp_arp_resolve(ip)) {
        return LITEETH_UDP_SUCCESS;
    }
    
    return LITEETH_UDP_ARP_FAILED;
}

int liteeth_udp_rx_queue_count(void) {
    return rx_queue_count_val;
}

int liteeth_udp_rx_pending(void) {
    return rx_queue_count_val > 0 ? 1 : 0;
}

void liteeth_udp_rx_queue_clear(void) {
    rx_queue_head = 0;
    rx_queue_tail = 0;
    rx_queue_count_val = 0;
    
    for (int i = 0; i < LITEETH_UDP_RX_QUEUE_SIZE; i++) {
        rx_queue[i].valid = 0;
    }
    
    DBG_PRINT("RX queue cleared\n");
}
