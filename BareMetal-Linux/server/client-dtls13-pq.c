#include <wolfssl/options.h>
#include <unistd.h>
#include <wolfssl/ssl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtls-pq-common.h"

static int sockfd = INVALID_SOCKET;
static WOLFSSL* ssl = NULL;
static WOLFSSL_CTX* ctx = NULL;

static void sig_handler(const int sig);
static void free_resources(void);

int main (int argc, char** argv) {
    int n = 0;
    int err;
    int ret;
    int exitVal = 1;
    struct sockaddr_in servAddr;
    char sendLine[MAXLINE];
    char recvLine[MAXLINE - 1];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <IP address>\n", argv[0]);
        return exitVal;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    wolfSSL_Debugging_ON();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        goto cleanup;
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, NULL)!= WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        goto cleanup;
    }

    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_512);
    if (ret < 0) {
        fprintf(stderr, "failed to set the requested group to WOLFSSL_ML_KEM_512.\n");
        goto cleanup;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);

    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) < 1) {
        perror("inet_pton()");
        goto cleanup;
    }

    if (wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr))
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_dtls_set_peer failed\n");
        goto cleanup;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
       perror("socket()");
       goto cleanup;
    }

    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "cannot set socket file descriptor\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
        fprintf(stderr, "wolfSSL_connect failed\n");
        goto cleanup;
    }

    showConnInfo(ssl);

    // sending datagram to server
    while (1) {
        if (fgets(sendLine, MAXLINE, stdin) == NULL)
            break;

        if (strncmp(sendLine, "exit", 4) == 0)
            break;

        if (wolfSSL_write(ssl, sendLine, strlen(sendLine)) != strlen(sendLine)) {

            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_write failed\n");

            goto cleanup;
        }

        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);

        if (n > 0) {
            recvLine[n] = '\0';
            printf("%s\n", recvLine);
        }
        else {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_read failed\n");
            goto cleanup;
        }
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
        int ret = wolfSSL_shutdown(ssl);

        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            ret = wolfSSL_shutdown(ssl);

        if (ret != WOLFSSL_SUCCESS) {

            int err = wolfSSL_get_error(ssl, 0);

            fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_shutdown failed\n");
        }

        wolfSSL_free(ssl);
        ssl = NULL;
    }

    if (sockfd != INVALID_SOCKET) {
        close(sockfd);
        sockfd = INVALID_SOCKET;
    }

    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }
}