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

#define MAXLINE   4096
static int sockfd = INVALID_SOCKET;
static WOLFSSL* ssl = NULL;
static WOLFSSL_CTX* ctx = NULL;
const char caCertLoc[] = "certs/mldsa65_root_cert.pem";

static void sig_handler(const int sig);
static void free_resources(void);
static inline void showConnInfo(WOLFSSL* ssl) {
    printf("Connection established using %s\n\n",wolfSSL_get_version(ssl));
}

int main (int argc, char** argv) {
    int n = 0;
    int err;
    int ret;
    int exitVal = 1;
    struct sockaddr_in servAddr;
    char sendLine[MAXLINE];
    char recvLine[MAXLINE - 1];

    if (argc != 3) {
        fprintf(stderr, "usage: %s <IP address> <Port>\n", argv[0]);
        return exitVal;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    // wolfSSL_Debugging_ON();

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
    servAddr.sin_port = htons(atoi(argv[2]));

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

    talk:
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

    WOLFSSL_SESSION* session = wolfSSL_get1_session(ssl);
    WOLFSSL* sslResume = wolfSSL_new(ctx);
    wolfSSL_shutdown(ssl);
    // wolfSSL_free(ssl);
    close(sockfd);

    printf("Client disconnected\n");
    printf("Do you want to resume the session? (y/n): ");
    char choice[3];
    if(fgets(choice, sizeof(choice), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        goto cleanup;
    }
    if (strncmp(choice,"y",1) != 0) {
        printf("Exiting without resuming session.\n");
        goto cleanup;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(atoi(argv[2]));
    if ( (inet_pton(AF_INET, argv[1], &servAddr.sin_addr)) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
    }

    if (wolfSSL_dtls_set_peer(sslResume, &servAddr, sizeof(servAddr))
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_dtls_set_peer failed\n");
        goto cleanup;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
       perror("socket()");
       goto cleanup;
    }

    if (wolfSSL_set_fd(sslResume, sockfd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "cannot set socket file descriptor\n");
        goto cleanup;
    }

    if(wolfSSL_set_session(sslResume, session)== SSL_SUCCESS) {
        printf("\nSession restored successfully\n");
    }
    else {
        printf("\nFailed to restore session\n");
        goto cleanup;
    }

    if (wolfSSL_connect(sslResume) != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(sslResume, 0);
        fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
        fprintf(stderr, "wolfSSL_connect failed\n");
        goto cleanup;
    }

    if (wolfSSL_session_reused(sslResume)) {
        printf("Reused session ID\n");
    } else {
        printf("Did not reuse session ID\n");
    }

    showConnInfo(sslResume);
    ssl = sslResume;
    goto talk;
    
    // wolfSSL_shutdown(ssl);
    // wolfSSL_free(sslResume);
    // close(sockfd);
cleanup:
    exitVal = 0;
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