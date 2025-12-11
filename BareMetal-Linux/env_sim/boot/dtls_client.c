#include <stdio.h>
#include <string.h>
#include "dtls_client.h"
#include "wolfssl_io.h"
#include "certs_buffer.h"

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>

static int g_system_initialized = 0;
static WC_RNG g_rng;

#define DTLS_DEBUG(fmt, ...) \
    printf("[DTLS_CLIENT] " fmt "\n", ##__VA_ARGS__)

#define DTLS_ERROR(fmt, ...) \
    printf("[DTLS_CLIENT ERROR] " fmt "\n", ##__VA_ARGS__)


int dtls_client_init_system(const uint8_t* mac, uint32_t ip) {
    int ret;
    
    if (g_system_initialized) {
        DTLS_DEBUG("System already initialized");
        return 0;
    }
    
    DTLS_DEBUG("Initializing DTLS client system...");
    
    ret = wc_InitRng(&g_rng);
    if (ret != 0) {
        DTLS_ERROR("Failed to initialize RNG: %d", ret);
        return -1;
    }
    
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_ERROR("wolfSSL_Init failed: %d", ret);
        wc_FreeRng(&g_rng);
        return -1;
    }
    
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
    
    ret = liteeth_init(mac, ip);
    if (ret != 0) {
        DTLS_ERROR("LiteETH init failed: %d", ret);
        wolfSSL_Cleanup();
        wc_FreeRng(&g_rng);
        return -1;
    }
    
    g_system_initialized = 1;
    DTLS_DEBUG("System initialization complete");
    
    return 0;
}

void dtls_client_cleanup_system(void) {
    if (g_system_initialized) {
        wolfSSL_Cleanup();
        wc_FreeRng(&g_rng);
        g_system_initialized = 0;
        DTLS_DEBUG("System cleanup complete");
    }
}

void dtls_client_config_init(dtls_client_config_t* config) {

    if (config == NULL) return;
    
    memset(config, 0, sizeof(dtls_client_config_t));
    
    config->server_port = DTLS_SERVER_PORT;
    config->local_port = DTLS_CLIENT_PORT;
    config->handshake_timeout = 30000;
    config->recv_timeout = 5000;
    config->verify_peer = 1;
    config->debug_enabled = 1;
}

void dtls_client_config_set_server(dtls_client_config_t* config, 
                                    uint32_t ip, uint16_t port) {

    if (config == NULL) return;
    config->server_ip = ip;
    config->server_port = port;
}

void dtls_client_config_set_ca_cert(dtls_client_config_t* config,
                                     const uint8_t* cert, size_t len) {

    if (config == NULL) return;
    config->ca_cert = cert;
    config->ca_cert_len = len;
}

int dtls_client_init(dtls_client_t* client, const dtls_client_config_t* config) {

    int ret;
    
    if (client == NULL || config == NULL) {
        DTLS_ERROR("Invalid parameters");
        return -1;
    }
    
    if (!g_system_initialized) {
        DTLS_ERROR("System not initialized - call dtls_client_init_system first");
        return -1;
    }
    
    memset(client, 0, sizeof(dtls_client_t));
    
    DTLS_DEBUG("Creating DTLS 1.3 client context...");
    
    
    client->ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (client->ctx == NULL) {
        DTLS_ERROR("wolfSSL_CTX_new failed");
        return -1;
    }
    
    
    ret = wolfssl_io_register_callbacks(client->ctx);
    if (ret != 0) {
        DTLS_ERROR("Failed to register IO callbacks");
        wolfSSL_CTX_free(client->ctx);
        return -1;
    }
    
    wolfssl_io_set_timeout(config->recv_timeout);
    
    if (config->ca_cert != NULL && config->ca_cert_len > 0) {
        DTLS_DEBUG("Loading CA certificate (%zu bytes)...", config->ca_cert_len);
        ret = wolfSSL_CTX_load_verify_buffer(client->ctx, 
                                              config->ca_cert, 
                                              (long)config->ca_cert_len,
                                              WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_ERROR("Failed to load CA certificate: %d", ret);
            wolfSSL_CTX_free(client->ctx);
            return -1;
        }
    } else if (config->verify_peer) {
        DTLS_ERROR("Peer verification enabled but no CA certificate provided");
        wolfSSL_CTX_free(client->ctx);
        return -1;
    }
    
    if (config->client_cert != NULL && config->client_cert_len > 0) {
        DTLS_DEBUG("Loading client certificate...");
        ret = wolfSSL_CTX_use_certificate_buffer(client->ctx,
                                                  config->client_cert,
                                                  (long)config->client_cert_len,
                                                  WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_ERROR("Failed to load client certificate: %d", ret);
            wolfSSL_CTX_free(client->ctx);
            return -1;
        }
    }
    
    if (config->client_key != NULL && config->client_key_len > 0) {
        DTLS_DEBUG("Loading client private key...");
        ret = wolfSSL_CTX_use_PrivateKey_buffer(client->ctx,
                                                 config->client_key,
                                                 (long)config->client_key_len,
                                                 WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_ERROR("Failed to load client private key: %d", ret);
            wolfSSL_CTX_free(client->ctx);
            return -1;
        }
    }
    
    if (config->verify_peer) {
        wolfSSL_CTX_set_verify(client->ctx, WOLFSSL_VERIFY_PEER, NULL);
    } else {
        wolfSSL_CTX_set_verify(client->ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    
    ret = liteeth_udp_ctx_init(&client->udp_ctx,
                               config->local_port,
                               config->server_ip,
                               config->server_port);
    if (ret != 0) {
        DTLS_ERROR("Failed to initialize UDP context");
        wolfSSL_CTX_free(client->ctx);
        return -1;
    }
    
    client->initialized = 1;
    DTLS_DEBUG("DTLS client initialized successfully");
    
    return 0;
}

void dtls_client_cleanup(dtls_client_t* client) {

    if (client == NULL) return;
    
    if (client->connected) {
        dtls_client_disconnect(client);
    }
    
    if (client->ssl != NULL) {
        wolfSSL_free(client->ssl);
        client->ssl = NULL;
    }
    
    if (client->ctx != NULL) {
        wolfSSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }
    
    liteeth_udp_ctx_free(&client->udp_ctx);
    
    client->initialized = 0;
    DTLS_DEBUG("DTLS client cleanup complete");
}

int dtls_client_connect(dtls_client_t* client) {

    int ret;
    int err;
    
    if (client == NULL || !client->initialized) {
        DTLS_ERROR("Client not initialized");
        return -1;
    }
    
    if (client->connected) {
        DTLS_DEBUG("Already connected");
        return 0;
    }
    
    DTLS_DEBUG("Creating SSL session...");
    
    
    client->ssl = wolfSSL_new(client->ctx);
    if (client->ssl == NULL) {
        DTLS_ERROR("wolfSSL_new failed");
        return -1;
    }
    
    
    DTLS_DEBUG("Setting ML-KEM-512 key share...");
    ret = wolfSSL_UseKeyShare(client->ssl, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_ERROR("Failed to set ML-KEM-512 key share: %d", ret);
        wolfSSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }
    
    wolfssl_io_set_udp_ctx(client->ssl, &client->udp_ctx);
    
    DTLS_DEBUG("Starting DTLS 1.3 handshake with " IP_FMT ":%d...",
               IP_ARGS(client->udp_ctx.remote_ip), 
               client->udp_ctx.remote_port);
    
    ret = wolfSSL_connect(client->ssl);
    
    if (ret != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(client->ssl, ret);
        DTLS_ERROR("wolfSSL_connect failed: error=%d (%s)", 
                   err, wolfSSL_ERR_reason_error_string(err));
        wolfSSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }
    
    client->connected = 1;
    
    DTLS_DEBUG("DTLS 1.3 handshake successful!");
    dtls_client_print_info(client);
    
    return 0;
}

int dtls_client_disconnect(dtls_client_t* client) {

    int ret;
    if (client == NULL || client->ssl == NULL) {
        return 0;
    }
    
    if (!client->connected) {
        return 0;
    }
    
    DTLS_DEBUG("Disconnecting...");
    
    ret = wolfSSL_shutdown(client->ssl);
    if (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
        
        ret = wolfSSL_shutdown(client->ssl);
    }
    
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(client->ssl, ret);
        DTLS_DEBUG("Shutdown warning: %d (%s)", 
                   err, wolfSSL_ERR_reason_error_string(err));
    }
    
    wolfSSL_free(client->ssl);
    client->ssl = NULL;
    client->connected = 0;
    
    DTLS_DEBUG("Disconnected");
    
    return 0;
}

int dtls_client_is_connected(dtls_client_t* client) {
    return (client != NULL && client->connected);
}

int dtls_client_send(dtls_client_t* client, const uint8_t* data, size_t len) {
    int ret;
    int err;
    
    if (client == NULL || !client->connected || client->ssl == NULL) {
        DTLS_ERROR("Not connected");
        return -1;
    }
    
    if (data == NULL || len == 0) {
        return 0;
    }
    
    ret = wolfSSL_write(client->ssl, data, (int)len);
    
    if (ret <= 0) {
        err = wolfSSL_get_error(client->ssl, ret);
        DTLS_ERROR("wolfSSL_write failed: %d (%s)", 
                   err, wolfSSL_ERR_reason_error_string(err));
        return -1;
    }
    
    DTLS_DEBUG("Sent %d bytes", ret);
    return ret;
}

int dtls_client_recv(dtls_client_t* client, uint8_t* buf, size_t len) {
    int ret;
    int err;
    
    if (client == NULL || !client->connected || client->ssl == NULL) {
        DTLS_ERROR("Not connected");
        return -1;
    }
    if (buf == NULL || len == 0) {
        return 0;
    }
    
    liteeth_service();
    ret = wolfSSL_read(client->ssl, buf, (int)len);
    if (ret <= 0) {
        err = wolfSSL_get_error(client->ssl, ret);
        
        if (err == WOLFSSL_ERROR_WANT_READ) {
            return 0;
        }
        if (err == WOLFSSL_ERROR_ZERO_RETURN) {
            DTLS_DEBUG("Connection closed by peer");
            client->connected = 0;
            return 0;
        }
        DTLS_ERROR("wolfSSL_read failed: %d (%s)", 
                   err, wolfSSL_ERR_reason_error_string(err));
        return -1;
    }
    
    DTLS_DEBUG("Received %d bytes", ret);
    return ret;
}

const char* dtls_client_get_cipher(dtls_client_t* client) {

    if (client == NULL || client->ssl == NULL) {
        return "N/A";
    }
    return wolfSSL_get_cipher(client->ssl);
}

const char* dtls_client_get_version(dtls_client_t* client) {

    if (client == NULL || client->ssl == NULL) {
        return "N/A";
    }
    return wolfSSL_get_version(client->ssl);
}

void dtls_client_print_info(dtls_client_t* client) {
    if (client == NULL || client->ssl == NULL) {
        return;
    }
    
    printf("\n=== DTLS Connection Info ===\n");
    printf("  Protocol: %s\n", wolfSSL_get_version(client->ssl));
    printf("  Cipher:   %s\n", wolfSSL_get_cipher(client->ssl));
    printf("  Server:   " IP_FMT ":%d\n", 
           IP_ARGS(client->udp_ctx.remote_ip),
           client->udp_ctx.remote_port);
    printf("============================\n\n");
}
