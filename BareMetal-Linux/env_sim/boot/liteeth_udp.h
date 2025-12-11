#ifndef LITEETH_UDP_H
#define LITEETH_UDP_H

#include <stdint.h>
#include <stddef.h>
#define LITEETH_DEFAULT_MAC     {0xaa, 0xb6, 0x24, 0x69, 0x77, 0x21};
#define LITEETH_DEFAULT_IP      IPTOINT(192, 168, 1, 100)  

#define LITEETH_RX_BUFFER_SIZE  4096
#define LITEETH_TX_BUFFER_SIZE  4096
#define LITEETH_MAX_PACKET_SIZE 1500

#define DTLS_CLIENT_PORT        12345
#define DTLS_SERVER_PORT        23456

typedef struct {
    uint32_t local_ip;          
    uint16_t local_port;        
    uint32_t remote_ip;         
    uint16_t remote_port;       
    
    uint8_t  rx_buffer[LITEETH_RX_BUFFER_SIZE];
    size_t   rx_data_len;       
    size_t   rx_read_pos;       
    
    int      initialized;       
    int      has_pending_data;  
} liteeth_udp_ctx_t;

int liteeth_init(const uint8_t* mac, uint32_t ip);
int liteeth_udp_ctx_init(liteeth_udp_ctx_t* ctx, 
                         uint16_t local_port,
                         uint32_t remote_ip, 
                         uint16_t remote_port);
void liteeth_udp_ctx_free(liteeth_udp_ctx_t* ctx);

int liteeth_udp_send(liteeth_udp_ctx_t* ctx, const uint8_t* data, size_t len);
int liteeth_udp_recv(liteeth_udp_ctx_t* ctx, uint8_t* buf, size_t len, uint32_t timeout_ms);
int liteeth_udp_data_available(liteeth_udp_ctx_t* ctx);

void liteeth_service(void);
int liteeth_arp_resolve(uint32_t ip);

#ifndef IPTOINT
#define IPTOINT(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)
#endif

#define IP_FMT "%d.%d.%d.%d"
#define IP_ARGS(ip) ((ip) >> 24) & 0xFF, ((ip) >> 16) & 0xFF, \
                    ((ip) >> 8) & 0xFF, (ip) & 0xFF

#endif 
