#include <stdio.h>
#include <string.h>
#include "dtls_client.h"
#include "wolfssl_io.h"
#include "certs_buffer.h"

#include "liteeth_udp.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/types.h>

static int dtls_want_read_or_write(int err) {
    return (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE ||
            err == WOLFSSL_ERROR_WANT_READ_E || err == WOLFSSL_ERROR_WANT_WRITE_E ||
            err == WANT_READ || err == WANT_WRITE ||
            err == WOLFSSL_CBIO_ERR_WANT_READ || err == WOLFSSL_CBIO_ERR_WANT_WRITE);
}

#define DTLS_CLIENT_DEBUG 0
#define DEBUG_WOLFSSL 0

#if DTLS_CLIENT_DEBUG
#define DTLS_DBG(fmt, ...) printf("[DTLS] " fmt, ##__VA_ARGS__)
#else
#define DTLS_DBG(fmt, ...)
#endif



static int g_system_initialized = 0;
int dtls_client_init_system(const uint8_t *mac, uint32_t ip) {
    int ret;
    
    if (g_system_initialized) {
        DTLS_DBG("System already initialized\n");
        return DTLS_CLIENT_SUCCESS;
    }
    
    DTLS_DBG("Initializing DTLS system...\n");
    
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_DBG("wolfSSL_Init failed: %d\n", ret);
        return DTLS_CLIENT_SSL_ERROR;
    }
    DTLS_DBG("wolfSSL initialized\n");
    
    #if DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
        DTLS_DBG("wolfSSL debugging enabled\n");
    #endif
    
    
    ret = liteeth_init(mac, ip);
    if (ret != LITEETH_UDP_SUCCESS) {
        DTLS_DBG("liteeth_init failed: %d\n", ret);
        wolfSSL_Cleanup();
        return DTLS_CLIENT_ERROR;
    }
    
    g_system_initialized = 1;
    DTLS_DBG("DTLS system initialized successfully\n");
    
    return DTLS_CLIENT_SUCCESS;
}

void dtls_client_cleanup_system(void) {
    if (!g_system_initialized) {
        return;
    }
    
    DTLS_DBG("Cleaning up DTLS system...\n");
    
    liteeth_udp_cleanup();
    wolfSSL_Cleanup();
    
    g_system_initialized = 0;
    DTLS_DBG("DTLS system cleaned up\n");
}

void dtls_client_config_init(dtls_client_config_t *config) {
    if (config == NULL) {
        return;
    }
    
    memset(config, 0, sizeof(dtls_client_config_t));
    config->local_port = DTLS_CLIENT_LOCAL_PORT;
    config->verify_peer = 1;
}

void dtls_client_config_set_server(dtls_client_config_t *config, uint32_t ip, uint16_t port) {
    if (config == NULL) {
        return;
    }
    
    config->server_ip = ip;
    config->server_port = port;
}

void dtls_client_config_set_ca_cert(dtls_client_config_t *config, const uint8_t *cert, size_t len) {
    if (config == NULL) {
        return;
    }
    
    config->ca_cert = cert;
    config->ca_cert_len = len;
}

int dtls_client_init(dtls_client_t *client, const dtls_client_config_t *config) {
    int ret;
    
    if (!g_system_initialized) {
        DTLS_DBG("System not initialized\n");
        return DTLS_CLIENT_NOT_INIT;
    }
    
    if (client == NULL || config == NULL) {
        return DTLS_CLIENT_ERROR;
    }
    
    memset(client, 0, sizeof(dtls_client_t));
    
    DTLS_DBG("Creating DTLS 1.3 client context...\n");
    
    client->ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (client->ctx == NULL) {
        DTLS_DBG("Failed to create wolfSSL context\n");
        return DTLS_CLIENT_SSL_ERROR;
    }
    
    ret = wolfssl_io_register_callbacks(client->ctx);
    if (ret != 0) {
        DTLS_DBG("Failed to set up I/O callbacks\n");
        wolfSSL_CTX_free(client->ctx);
        return DTLS_CLIENT_ERROR;
    }
    
    ret = wolfSSL_CTX_UseSupportedCurve(client->ctx, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_DBG("Warning: Failed to set ML-KEM-512 support: %d\n", ret);
    } else {
        DTLS_DBG("ML-KEM-512 key exchange enabled\n");
    }
    
    if (config->verify_peer && config->ca_cert != NULL && config->ca_cert_len > 0) {
        DTLS_DBG("Loading CA certificate (%u bytes)...\n", (unsigned)config->ca_cert_len);
        
        ret = wolfSSL_CTX_load_verify_buffer(client->ctx, config->ca_cert, (long)config->ca_cert_len, WOLFSSL_FILETYPE_ASN1);
        
        if (ret != WOLFSSL_SUCCESS) {
            ret = wolfSSL_CTX_load_verify_buffer(client->ctx, config->ca_cert, (long)config->ca_cert_len, WOLFSSL_FILETYPE_PEM);
        }
        
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_DBG("Failed to load CA certificate: %d\n", ret);
            wolfSSL_CTX_free(client->ctx);
            return DTLS_CLIENT_CERT_ERROR;
        }
        DTLS_DBG("CA certificate loaded\n");
        
        wolfSSL_CTX_set_verify(client->ctx, WOLFSSL_VERIFY_PEER, NULL);

    } else {
        DTLS_DBG("Peer verification disabled\n");
        wolfSSL_CTX_set_verify(client->ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    
    if (config->client_cert != NULL && config->client_cert_len > 0) {
        ret = wolfSSL_CTX_use_certificate_buffer(client->ctx, config->client_cert, (long)config->client_cert_len, WOLFSSL_FILETYPE_ASN1);
        
        if (ret != WOLFSSL_SUCCESS) {
            ret = wolfSSL_CTX_use_certificate_buffer(client->ctx, config->client_cert, (long)config->client_cert_len, WOLFSSL_FILETYPE_PEM);
        }
        
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_DBG("Failed to load client certificate: %d\n", ret);
            wolfSSL_CTX_free(client->ctx);
            return DTLS_CLIENT_CERT_ERROR;
        }
        DTLS_DBG("Client certificate loaded\n");
    }
    
    if (config->client_key != NULL && config->client_key_len > 0) {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(client->ctx,
                                                 config->client_key,
                                                 (long)config->client_key_len,
                                                 WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            ret = wolfSSL_CTX_use_PrivateKey_buffer(client->ctx,
                                                     config->client_key,
                                                     (long)config->client_key_len,
                                                     WOLFSSL_FILETYPE_PEM);
        }
        
        if (ret != WOLFSSL_SUCCESS) {
            DTLS_DBG("Failed to load client private key: %d\n", ret);
            wolfSSL_CTX_free(client->ctx);
            return DTLS_CLIENT_CERT_ERROR;
        }
        DTLS_DBG("Client private key loaded\n");
    }
    
    DTLS_DBG("Creating SSL session...\n");
    client->ssl = wolfSSL_new(client->ctx);
    if (client->ssl == NULL) {
        DTLS_DBG("Failed to create SSL session\n");
        wolfSSL_CTX_free(client->ctx);
        return DTLS_CLIENT_SSL_ERROR;
    }
    
    ret = wolfSSL_UseKeyShare(client->ssl, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_DBG("Warning: Failed to set ML-KEM-512 key share: %d\n", ret);
    }
    
    // ret = wolfSSL_dtls_set_mtu(client->ssl, 1400);
    // if (ret != WOLFSSL_SUCCESS) {
    //     DTLS_DBG("Warning: Failed to set DTLS MTU: %d\n", ret);
    // } else {
    //     DTLS_DBG("DTLS MTU set to 1400\n");
    // }
    
    wolfSSL_dtls13_set_send_more_acks(client->ssl, 1);
    DTLS_DBG("Enabled aggressive ACK sending for DTLS 1.3\n");
    
    DTLS_DBG("Setting up UDP connection to " IP_FMT ":%u...\n",
             IP_ARGS(config->server_ip), config->server_port);
    
    ret = liteeth_udp_connect(&client->udp_ctx, config->local_port, config->server_ip, config->server_port);
    if (ret != LITEETH_UDP_SUCCESS) {
        DTLS_DBG("Failed to connect UDP: %d\n", ret);
        wolfSSL_free(client->ssl);
        wolfSSL_CTX_free(client->ctx);
        return DTLS_CLIENT_CONNECT_ERROR;
    }
    
    ret = wolfssl_io_set_udp_ctx(client->ssl, &client->udp_ctx);
    if (ret != 0) {
        DTLS_DBG("Failed to set I/O context\n");
        liteeth_udp_close(&client->udp_ctx);
        wolfSSL_free(client->ssl);
        wolfSSL_CTX_free(client->ctx);
        return DTLS_CLIENT_ERROR;
    }
    
    client->initialized = 1;
    DTLS_DBG("DTLS client initialized\n");
    
    return DTLS_CLIENT_SUCCESS;
}

int dtls_client_connect(dtls_client_t *client) {
    int ret;
    int err;
    int attempts = 0;
    int timeout_count = 0;
    const int max_attempts = 5000;
    
    if (client == NULL || !client->initialized) {
        return DTLS_CLIENT_NOT_INIT;
    }
    
    DTLS_DBG("Starting DTLS handshake...\n");
    
    do {
        ret = wolfSSL_connect(client->ssl);
        
        if (ret == WOLFSSL_SUCCESS) {
            break;
        }
        
        err = wolfSSL_get_error(client->ssl, ret);

        if (dtls_want_read_or_write(err)) {
            /* Service the network once per WANT_* to avoid burning cycles in sim. */
            liteeth_udp_service();

            /* Every so often, ask wolfSSL to handle DTLS retransmission timers. */
            if ((attempts % 64) == 0) {
                (void)wolfSSL_dtls_get_current_timeout(client->ssl);
                timeout_count++;
                if (timeout_count >= 4) {
                    ret = wolfSSL_dtls_got_timeout(client->ssl);
                    if (ret == WOLFSSL_SUCCESS) {
                        timeout_count = 0;
                    }
                }
            }

            attempts++;
            continue;
        }
        
        DTLS_DBG("Handshake failed (err=%d, ret=%d)\n", err, ret);
        
        return DTLS_CLIENT_CONNECT_ERROR;
        
    } while (attempts < max_attempts);
    
    if (ret != WOLFSSL_SUCCESS) {
        DTLS_DBG("Handshake timeout after %d attempts\n", attempts);
        return DTLS_CLIENT_CONNECT_ERROR;
    }
    
    client->connected = 1;
    
    DTLS_DBG("DTLS connection established!\n");
    DTLS_DBG("Protocol: %s\n", wolfSSL_get_version(client->ssl));
    DTLS_DBG("Cipher: %s\n", wolfSSL_get_cipher(client->ssl));
    
    return DTLS_CLIENT_SUCCESS;
}

int dtls_client_send(dtls_client_t *client, const uint8_t *data, size_t len) {
    int ret;
    int err;
    int attempts = 0;
    const int max_attempts = 200;
    
    if (client == NULL || !client->connected) {
        return DTLS_CLIENT_NOT_INIT;
    }
    
    DTLS_DBG("Sending %u bytes...\n", (unsigned)len);
    
    do {
        ret = wolfSSL_write(client->ssl, data, (int)len);
        if (ret > 0) {
            break;
        }

        err = wolfSSL_get_error(client->ssl, ret);
        if (dtls_want_read_or_write(err)) {
            liteeth_udp_service();
            attempts++;
            continue;
        }

        DTLS_DBG("Send failed: error %d\n", err);
        return DTLS_CLIENT_ERROR;
    } while (attempts < max_attempts);

    if (ret <= 0) {
        DTLS_DBG("Send timeout (last ret=%d)\n", ret);
        return 0;
    }
    
    DTLS_DBG("Sent %d bytes\n", ret);
    return ret;
}

int dtls_client_recv(dtls_client_t *client, uint8_t *buf, size_t maxlen) {
    int ret;
    int err;
    int attempts = 0;
    const int max_attempts = 50;
    
    if (client == NULL || !client->connected) {
        return DTLS_CLIENT_NOT_INIT;
    }
    
    DTLS_DBG("Receiving (max %u bytes)...\n", (unsigned)maxlen);
    
    do {
        ret = wolfSSL_read(client->ssl, buf, (int)maxlen);
        
        if (ret > 0) {
            DTLS_DBG("Received %d bytes\n", ret);
            return ret;
        }
        
        err = wolfSSL_get_error(client->ssl, ret);

        if (dtls_want_read_or_write(err)) {
            liteeth_udp_service();
            attempts++;
            continue;
        }
        
        if (err == WOLFSSL_ERROR_ZERO_RETURN) {
            DTLS_DBG("Connection closed by peer\n");
            client->connected = 0;
            return 0;
        }
        
        DTLS_DBG("Receive failed: error %d\n", err);
        return DTLS_CLIENT_ERROR;
        
    } while (attempts < max_attempts);
    
    DTLS_DBG("Receive timeout\n");
    return 0;
}

void dtls_client_disconnect(dtls_client_t *client) {
    if (client == NULL || !client->connected) {
        return;
    }
    
    DTLS_DBG("Disconnecting...\n");
    
    int ret = wolfSSL_shutdown(client->ssl);
    if (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
        wolfSSL_shutdown(client->ssl);
    }
    
    client->connected = 0;
    
    DTLS_DBG("Disconnected\n");
}

void dtls_client_cleanup(dtls_client_t *client) {
    if (client == NULL) {
        return;
    }
    
    DTLS_DBG("Cleaning up client...\n");
    
    if (client->connected) {
        dtls_client_disconnect(client);
    }
    
    liteeth_udp_close(&client->udp_ctx);
    
    if (client->ssl != NULL) {
        wolfSSL_free(client->ssl);
        client->ssl = NULL;
    }
    
    if (client->ctx != NULL) {
        wolfSSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }
    
    client->initialized = 0;
    
    DTLS_DBG("Client cleaned up\n");
}

int dtls_client_get_conn_info(dtls_client_t *client, char *buf, size_t maxlen) {
    if (client == NULL || buf == NULL || maxlen == 0) {
        return 0;
    }
    
    if (!client->connected) {
        return snprintf(buf, maxlen, "Not connected");
    }
    
    return snprintf(buf, maxlen, "Protocol: %s, Cipher: %s", wolfSSL_get_version(client->ssl), wolfSSL_get_cipher(client->ssl));
}
