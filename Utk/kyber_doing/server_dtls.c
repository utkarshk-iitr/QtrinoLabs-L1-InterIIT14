#include <wolfssl/options.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <wolfssl/wolfcrypt/aes.h>
#include <netdb.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <wolfssl/ssl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define MAXLINE 4096
const char caCertLoc[] = "./certs/ca_cert.pem";
const char servCertLoc[] = "./certs/server_cert.pem";
const char servKeyLoc[] = "./certs/server_key.pem";

static inline void show_conn_info(WOLFSSL *ssl){
    printf("\nNew connection established using %s", wolfSSL_get_version(ssl));
}

int generate_certificates()
{
    return system("cd certs && ./certs_generator.sh");
}

WOLFSSL_CTX *ctx = NULL;
WOLFSSL *ssl = NULL;
int listenfd = INVALID_SOCKET;

static void sig_handler(const int sig);
static void free_resources(void);

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <Port>\n", argv[0]);
        return 1;
    }
    
    // if(generate_certificates()!=0){
    //     fprintf(stderr, "Certificate generation failed\n");
    //     return 1;
    // }

    int exitVal = 1;
    struct sockaddr_in servAddr;
    struct sockaddr_in cliaddr;
    int ret;
    int err;
    int recvLen = 0;
    socklen_t cliLen;
    char buff[MAXLINE];
    char ack[] = "ACK: Message Got\n";

    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    wolfSSL_Debugging_ON();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method())) == NULL)
    {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        goto cleanup;
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, 0) !=WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, servCertLoc,WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Error loading %s, please check the file.\n", servCertLoc);
        goto cleanup;
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, servKeyLoc,WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Error loading %s, please check the file.\n", servKeyLoc);
        goto cleanup;
    }

    if (wolfSSL_CTX_check_private_key(ctx) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        goto cleanup;
    }

    if (wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Failed to set ML-KEM group\n");
        goto cleanup;
    }
    printf("DTLS configured with WOLFSSL_ML_KEM_512\n");

    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket()");
        goto cleanup;
    }

    memset((char *)&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(atoi(argv[1]));

    if (bind(listenfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("bind()");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    while (1)
    {
        printf("Awaiting client connection on port %d\n", atoi(argv[1]));

        cliLen = sizeof(cliaddr);
        ret = (int)recvfrom(listenfd, (char *)&buff, sizeof(buff), MSG_PEEK, (struct sockaddr *)&cliaddr, &cliLen);

        if (ret < 0)
        {
            perror("recvfrom()");
            goto cleanup;
        }
        else if (ret == 0)
        {
            fprintf(stderr, "recvfrom zero return\n");
            goto cleanup;
        }

        if ((ssl = wolfSSL_new(ctx)) == NULL)
        {
            fprintf(stderr, "wolfSSL_new error.\n");
            goto cleanup;
        }

        if (wolfSSL_dtls_set_peer(ssl, &cliaddr, cliLen) != WOLFSSL_SUCCESS)
        {
            fprintf(stderr, "wolfSSL_dtls_set_peer error.\n");
            goto cleanup;
        }

        if (wolfSSL_set_fd(ssl, listenfd) != WOLFSSL_SUCCESS)
        {
            fprintf(stderr, "wolfSSL_set_fd error.\n");
            break;
        }

        if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS)
        {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "error = %d, %s\n", err,
                    wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "SSL_accept failed.\n");
            goto cleanup;
        }

        show_conn_info(ssl);

        unsigned char key_material[32];
        const char *label = "EXPORTER-key-for-aes-ctr";

        ret = wolfSSL_export_keying_material(ssl, key_material, sizeof(key_material),label, strlen(label), NULL, 0, 0);
        if (ret != WOLFSSL_SUCCESS)
        {
            fprintf(stderr, "Failed to export keying material\n");
            goto cleanup;
        }

        printf("\nExtracted Shared Secret from ML-KEM Key Exchange\n");
        // printf("Shared Secret (32 bytes for AES-256-CTR): ");
        // for (unsigned int i = 0; i < sizeof(key_material); i++) {
        //     printf("%02x", key_material[i]);
        // }
        // printf("\n\n");

        Aes aes_enc, aes_dec;
        unsigned char iv_enc[AES_BLOCK_SIZE];
        unsigned char iv_dec[AES_BLOCK_SIZE];
        memset(iv_enc, 0, AES_BLOCK_SIZE);
        memset(iv_dec, 0, AES_BLOCK_SIZE);

        if (wc_AesSetKey(&aes_enc, key_material, sizeof(key_material), iv_enc, AES_ENCRYPTION) != 0)
        {
            fprintf(stderr, "Failed to set AES encryption key\n");
            goto cleanup;
        }

        if (wc_AesSetKey(&aes_dec, key_material, sizeof(key_material), iv_dec, AES_ENCRYPTION) != 0)
        {
            fprintf(stderr, "Failed to set AES decryption key\n");
            goto cleanup;
        }

        while (1)
        {
            if ((recvLen = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) > 0)
            {
                unsigned char decrypted[MAXLINE];

                // printf("[Received %d encrypted bytes] ", recvLen);

                if (wc_AesCtrEncrypt(&aes_dec, decrypted, (unsigned char *)buff, recvLen) != 0)
                {
                    fprintf(stderr, "AES decryption failed\n");
                    goto cleanup;
                }

                decrypted[recvLen] = '\0';
                printf("\nDecrypted: %s[Decrypted %d bytes]\n", decrypted, recvLen);
            }
            else if (recvLen <= 0)
            {
                err = wolfSSL_get_error(ssl, 0);
                if (err == WOLFSSL_ERROR_ZERO_RETURN)
                    break;
                fprintf(stderr, "error = %d, %s\n", err,wolfSSL_ERR_reason_error_string(err));
                fprintf(stderr, "SSL_read failed.\n");
                goto cleanup;
            }

            unsigned char encrypted_ack[MAXLINE];

            if (wc_AesCtrEncrypt(&aes_enc, encrypted_ack, (unsigned char *)ack, sizeof(ack)) != 0)
            {
                fprintf(stderr, "AES encryption failed\n");
                goto cleanup;
            }

            // printf("[Sending encrypted reply of %lu bytes]\n\n", sizeof(ack));
            printf("Sending encrypted ACK\n");

            if (wolfSSL_write(ssl, encrypted_ack, sizeof(ack)) < 0)
            {
                err = wolfSSL_get_error(ssl, 0);
                fprintf(stderr, "error = %d, %s\n", err,wolfSSL_ERR_reason_error_string(err));
                fprintf(stderr, "wolfSSL_write failed.\n");
                goto cleanup;
            }
        }

        // printf("reply sent %s\n", ack);

        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            ret = wolfSSL_shutdown(ssl);
        if (ret != WOLFSSL_SUCCESS)
        {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err,wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_shutdown failed\n");
        }
        wolfSSL_free(ssl);
        ssl = NULL;

        printf("\nAwaiting new connection\n");
    }

    exitVal = 0;
cleanup:
    free_resources();
    wolfSSL_Cleanup();

    return exitVal;
}

static void sig_handler(const int sig)
{
    (void)sig;
    free_resources();
    wolfSSL_Cleanup();
}

static void free_resources(void)
{
    if (ssl != NULL)
    {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = NULL;
    }
    if (ctx != NULL)
    {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }
    if (listenfd != INVALID_SOCKET)
    {
        close(listenfd);
        listenfd = INVALID_SOCKET;
    }
}