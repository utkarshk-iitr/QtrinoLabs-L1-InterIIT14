/*
 * client-dtls13.c
 * To exit the sending loop enter "end" or Ctrl+D
 */

#include <wolfssl/options.h>
#include <unistd.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtls-common.h"

int main (int argc, char** argv)
{
    /* standard variables used in a dtls client */
    int             n = 0;
    int             sockfd = INVALID_SOCKET;
    int             err;
    int             ret;
    int             exitVal = 1;
    struct          sockaddr_in servAddr;
    WOLFSSL*        ssl = NULL;
    WOLFSSL_CTX*    ctx = NULL;
    char            sendLine[MAXLINE];
    char            recvLine[MAXLINE - 1];

    /* Program argument checking */
    if (argc != 3) {
        fprintf(stderr, "usage: %s <IP address> <Port>\n", argv[0]);
        return exitVal;
    }

    /* Initialize wolfSSL before assigning ctx */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    /* No-op when debugging is not compiled in */
    wolfSSL_Debugging_ON();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        goto cleanup;
    }

    /* Load certificates into ctx variable */
    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, NULL)
	    != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    /* Set single supported curve/group to prevent multiple key shares */
    if (wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_1024) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to set ML-KEM group\n");
        goto cleanup;
    }
    printf("DTLS configured with WOLFSSL_ML_KEM_512\n");

    /* Assign ssl variable */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "unable to get ssl object\n");
        goto cleanup;
    }

    /* servAddr setup */
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

    /* Set the file descriptor for ssl */
    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "cannot set socket file descriptor\n");
        goto cleanup;
    }

    /* Perform SSL connection */
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
        fprintf(stderr, "wolfSSL_connect failed\n");
        goto cleanup;
    }

    showConnInfo(ssl);

    /* Extract shared secret derived from ML-KEM key exchange for later AES-GCM encryption */
    unsigned char key_material[32];  /* 256-bit key for AES-256-GCM */
    const char* label = "EXPORTER-key-for-aes-ctr";
    
    ret = wolfSSL_export_keying_material(ssl, key_material, sizeof(key_material), 
                                          label, strlen(label), NULL, 0, 0);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to export keying material\n");
        goto cleanup;
    }

    printf("\nExtracted Shared Secret from ML-KEM Key Exchange\n\n");
    // printf("Shared Secret (32 bytes for AES-256-CTR): ");
    // for (unsigned int i = 0; i < sizeof(key_material); i++) {
    //     printf("%02x", key_material[i]);
    // }
    // printf("\n\n");

    /* Initialize AES context for encryption and decryption */
    Aes aes_enc, aes_dec;
    unsigned char iv_enc[AES_BLOCK_SIZE];
    unsigned char iv_dec[AES_BLOCK_SIZE];
    
    /* Initialize IVs (in production, use proper IV management) */
    memset(iv_enc, 0, AES_BLOCK_SIZE);
    memset(iv_dec, 0, AES_BLOCK_SIZE);
    
    if (wc_AesSetKey(&aes_enc, key_material, sizeof(key_material), iv_enc, AES_ENCRYPTION) != 0) {
        fprintf(stderr, "Failed to set AES encryption key\n");
        goto cleanup;
    }
    
    if (wc_AesSetKey(&aes_dec, key_material, sizeof(key_material), iv_dec, AES_ENCRYPTION) != 0) {
        fprintf(stderr, "Failed to set AES decryption key\n");
        goto cleanup;
    }
    

    while (1) {
        if (fgets(sendLine, MAXLINE, stdin) == NULL)
            break;

        if (strncmp(sendLine, "exit", 4) == 0){
            wolfSSL_write(ssl,"",0);
            break;
        }

        int msgLen = strlen(sendLine);
        unsigned char encrypted[MAXLINE];
        
        /* Encrypt the message using AES-CTR */
        if (wc_AesCtrEncrypt(&aes_enc, encrypted, (unsigned char*)sendLine, msgLen) != 0) {
            fprintf(stderr, "AES encryption failed\n");
            goto cleanup;
        }
        
        printf("[Encrypted %d bytes] \n", msgLen);

        /* Send encrypted message to the server */
        if (wolfSSL_write(ssl, encrypted, msgLen) != msgLen) {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err,
                wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_write failed\n");
            goto cleanup;
        }

        /* n is the # of bytes received */
        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);

        if (n > 0) {
            unsigned char decrypted[MAXLINE];
            
            /* Decrypt the received message using AES-CTR */
            if (wc_AesCtrEncrypt(&aes_dec, decrypted, (unsigned char*)recvLine, n) != 0) {
                fprintf(stderr, "AES decryption failed\n");
                goto cleanup;
            }
            
            /* Add a terminating character */
            decrypted[n] = '\0';
            printf("%s[Decrypted %d bytes]\n\n", decrypted,n);
        }
        else {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err,
                wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_read failed\n");
            goto cleanup;
        }
    }
/*                End code for sending datagram to server                    */
/*****************************************************************************/

    exitVal = 0;
cleanup:
    if (ssl != NULL) {
        /* Attempt a full shutdown */
        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            ret = wolfSSL_shutdown(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            err = wolfSSL_get_error(ssl, 0);
            // fprintf(stderr, "err = %d, %s\n", err,wolfSSL_ERR_reason_error_string(err));
            // fprintf(stderr, "wolfSSL_shutdown failed\n");
        }
        wolfSSL_free(ssl);
    }
    if (sockfd != INVALID_SOCKET)
        close(sockfd);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return exitVal;
}
