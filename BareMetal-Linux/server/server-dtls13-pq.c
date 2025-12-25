#include <wolfssl/options.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wolfssl/ssl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "dtls-pq-common.h"

int listenfd = INVALID_SOCKET;
WOLFSSL*  ssl = NULL;
WOLFSSL_CTX*  ctx = NULL;


static void sig_handler(const int sig);
static void free_resources(void);

int main(int argc, char** argv) {
    int exitVal = 1;
    struct sockaddr_in servAddr;
    struct sockaddr_in cliaddr;
    int ret;
    int err;
    int recvLen = 0;
    socklen_t cliLen;
    char buff[MAXLINE];
    char ack[] = "I hear you fashizzle!\n";

    (void)argc;
    (void)argv;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    // wolfSSL_Debugging_ON();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        goto cleanup;
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, 0) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }
    
    if (wolfSSL_CTX_use_certificate_file(ctx, servCertLoc, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", servCertLoc);
        goto cleanup;
    }
    
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, servKeyLoc, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", servKeyLoc);
        goto cleanup;
    }

    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket()");
        goto cleanup;
    }
    printf("Socket allocated\n");
    memset((char *)&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    if (bind(listenfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("bind()");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    while (1) {
        printf("Awaiting client connection on port %d\n", SERV_PORT);

        cliLen = sizeof(cliaddr);
        ret = (int)recvfrom(listenfd, (char *)&buff, sizeof(buff), MSG_PEEK, (struct sockaddr*)&cliaddr, &cliLen);

        if (ret < 0) {
            perror("recvfrom()");
            goto cleanup;
        }

        else if (ret == 0) {
            fprintf(stderr, "recvfrom zero return\n");
            goto cleanup;
        }

        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "wolfSSL_new error.\n");
            goto cleanup;
        }

        ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_512);
        if (ret < 0) {
            fprintf(stderr, "ERROR: failed to set the requested group to WOLFSSL_ML_KEM_512.\n");
            goto cleanup;
        }

        // enable fragmented ClientHello support
        if (wolfSSL_dtls13_allow_ch_frag(ssl, 1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_dtls13_allow_ch_frag failed.\n");
            goto cleanup;
        }

        // ret = wolfSSL_dtls_set_mtu(ssl, 1400);
        // if (ret != WOLFSSL_SUCCESS) {
        //     fprintf(stderr, "Warning: Failed to set DTLS MTU: %d\n", ret);
        // } else {
        //     printf("DTLS MTU set to 1400\n");
        // }

        wolfSSL_dtls13_set_send_more_acks(ssl, 1);
        printf("Enabled aggressive ACK sending for DTLS 1.3\n");
        if (wolfSSL_dtls_set_peer(ssl, &cliaddr, cliLen) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_dtls_set_peer error.\n");
            goto cleanup;
        }

        if (wolfSSL_set_fd(ssl, listenfd) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_set_fd error.\n");
            break;
        }

        if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {

            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "error = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "SSL_accept failed.\n");

            goto cleanup;
        }

        showConnInfo(ssl);

        while (1) {
            if ((recvLen = wolfSSL_read(ssl, buff, sizeof(buff)-1)) > 0) {
                printf("heard %d bytes\n", recvLen);

                buff[recvLen] = '\0';
                printf("I heard this: %s", buff);
            }
            else if (recvLen <= 0) {
                err = wolfSSL_get_error(ssl, 0);

                if (err == WOLFSSL_ERROR_ZERO_RETURN)
                    break;

                fprintf(stderr, "error = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
                fprintf(stderr, "SSL_read failed.\n");

                goto cleanup;
            }
            
            printf("Sending reply.\n");

            if (wolfSSL_write(ssl, ack, sizeof(ack)) < 0) {
                err = wolfSSL_get_error(ssl, 0);

                fprintf(stderr, "error = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
                fprintf(stderr, "wolfSSL_write failed.\n");

                goto cleanup;
            }
        }

        printf("reply sent \"%s\"\n", ack);

        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            ret = wolfSSL_shutdown(ssl);

        if (ret != WOLFSSL_SUCCESS) {

            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));

            fprintf(stderr, "wolfSSL_shutdown failed\n");
        }
        wolfSSL_free(ssl);
        ssl = NULL;

        printf("Awaiting new connection\n");
    }

    exitVal = 0;

cleanup:
    free_resources();
    wolfSSL_Cleanup();

    return exitVal;
}


static void sig_handler(const int sig) {
    (void)sig;
    free_resources();
    wolfSSL_Cleanup();
    exit(0);
}

static void free_resources(void) {
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = NULL;
    }
    
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }
    
    if (listenfd != INVALID_SOCKET) {
        close(listenfd);
        listenfd = INVALID_SOCKET;
    }
}