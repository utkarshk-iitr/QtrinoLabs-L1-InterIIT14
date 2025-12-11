#ifndef DTLS_CLIENT_H
#define DTLS_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/ssl.h>
#include "liteeth_udp.h"


typedef struct {
    
    uint32_t server_ip;         
    uint16_t server_port;       
    uint16_t local_port;        
    
    
    uint32_t handshake_timeout; 
    uint32_t recv_timeout;      
    
    
    const uint8_t* ca_cert;     
    size_t ca_cert_len;
    
    const uint8_t* client_cert; 
    size_t client_cert_len;
    
    const uint8_t* client_key;  
    size_t client_key_len;
    
    
    int verify_peer;            
    int debug_enabled;          
} dtls_client_config_t;


typedef struct {
    WOLFSSL_CTX* ctx;           
    WOLFSSL* ssl;               
    liteeth_udp_ctx_t udp_ctx;  
    
    int connected;              
    int initialized;            
} dtls_client_t;

int dtls_client_init_system(const uint8_t* mac, uint32_t ip);
void dtls_client_cleanup_system(void);
int dtls_client_init(dtls_client_t* client, const dtls_client_config_t* config);
void dtls_client_cleanup(dtls_client_t* client);
int dtls_client_connect(dtls_client_t* client);
int dtls_client_disconnect(dtls_client_t* client);
int dtls_client_is_connected(dtls_client_t* client);
int dtls_client_send(dtls_client_t* client, const uint8_t* data, size_t len);
int dtls_client_recv(dtls_client_t* client, uint8_t* buf, size_t len);

const char* dtls_client_get_cipher(dtls_client_t* client);
const char* dtls_client_get_version(dtls_client_t* client);


void dtls_client_print_info(dtls_client_t* client);
void dtls_client_config_init(dtls_client_config_t* config);
void dtls_client_config_set_server(dtls_client_config_t* config, 
                                    uint32_t ip, uint16_t port);
void dtls_client_config_set_ca_cert(dtls_client_config_t* config,
                                     const uint8_t* cert, size_t len);

#endif 
