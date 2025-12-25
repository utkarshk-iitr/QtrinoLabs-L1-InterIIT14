#ifndef LITEETH_UDP_H
#define LITEETH_UDP_H

#include <stdint.h>
#include <stddef.h>

#define LITEETH_UDP_MAX_PACKET_SIZE     1500
#define LITEETH_UDP_RX_QUEUE_SIZE       16
#define LITEETH_UDP_TX_TIMEOUT_MS       5000
#define LITEETH_UDP_RX_TIMEOUT_MS       5000

// for debug
#define IPTOINT(a, b, c, d) ((a << 24)|(b << 16)|(c << 8)|d)
#define IP_FMT "%u.%u.%u.%u"
#define IP_ARGS(ip) (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF)

#define LITEETH_UDP_SUCCESS         0
#define LITEETH_UDP_ERROR          -1
#define LITEETH_UDP_TIMEOUT        -2
#define LITEETH_UDP_QUEUE_FULL     -3
#define LITEETH_UDP_QUEUE_EMPTY    -4
#define LITEETH_UDP_ARP_FAILED     -5
#define LITEETH_UDP_NOT_INIT       -6
#define LITEETH_UDP_WOULD_BLOCK    -7

typedef struct {
    uint8_t  data[LITEETH_UDP_MAX_PACKET_SIZE];
    uint32_t len;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int      valid;
} liteeth_packet_t;


typedef struct {
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    int      initialized;
    int      connected;
} liteeth_udp_ctx_t;

int liteeth_init(const uint8_t *mac, uint32_t ip);
void liteeth_udp_cleanup(void);
int liteeth_udp_connect(liteeth_udp_ctx_t *ctx, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port);
void liteeth_udp_close(liteeth_udp_ctx_t *ctx);
int liteeth_udp_send(liteeth_udp_ctx_t *ctx, const uint8_t *data, size_t len);
int liteeth_udp_recv(liteeth_udp_ctx_t *ctx, uint8_t *buf, size_t maxlen, uint32_t timeout_ms);
int liteeth_udp_recv_nonblock(liteeth_udp_ctx_t *ctx, uint8_t *buf, size_t maxlen);
void liteeth_udp_service(void);
int liteeth_udp_arp_resolve(uint32_t ip);
int liteeth_udp_rx_queue_count(void);
int liteeth_udp_rx_pending(void);
void liteeth_udp_rx_queue_clear(void);

#endif /* LITEETH_UDP_H */