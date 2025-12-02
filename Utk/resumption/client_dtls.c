// To exit the sending loop enter "exit" or Ctrl+D

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

#define MAXLINE 4096
const char caCertLoc[] = "./certs/ca_cert.pem";
const char servCertLoc[] = "./certs/server_cert.pem";
const char servKeyLoc[] = "./certs/server_key.pem";

static inline void show_conn_info(WOLFSSL *ssl){
    printf("\nNew connection established using %s", wolfSSL_get_version(ssl));
}

int main(int argc, char **argv)
{
    int n = 0;
    int sockfd = INVALID_SOCKET;
    int err;
    int ret;
    int exitVal = 1;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    WOLFSSL *ssl = NULL;
    WOLFSSL_CTX *ctx = NULL;
    char sendLine[MAXLINE];
    char recvLine[MAXLINE - 1];

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <Client Port> <Server IP> <Server Port>\n", argv[0]);
        return exitVal;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "wolfSSL_Init error.\n");
        return exitVal;
    }

    wolfSSL_Debugging_ON();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method())) == NULL)
    {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        goto cleanup;
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, caCertLoc, NULL) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    if (wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ML_KEM_512) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Failed to set ML-KEM group\n");
        goto cleanup;
    }
    printf("DTLS configured with WOLFSSL_ML_KEM_512\n");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "unable to get ssl object\n");
        goto cleanup;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(atoi(argv[3]));

    if (inet_pton(AF_INET, argv[2], &servAddr.sin_addr) < 1)
    {
        perror("inet_pton()");
        goto cleanup;
    }

    if (wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr)) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "wolfSSL_dtls_set_peer failed\n");
        goto cleanup;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket()");
        goto cleanup;
    }

    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clientAddr.sin_port = htons(atoi(argv[1]));

    if (bind(sockfd, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0)
    {
        perror("bind()");
        goto cleanup;
    }
    
    printf("Client bound to port %s\n", argv[1]);
    unsigned char key_material[32];

    char init_msg = 0;
    if (sendto(sockfd, &init_msg, 1, 0, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        perror("sendto()");
        goto cleanup;
    }

    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "cannot set socket file descriptor\n");
        goto cleanup;
    }

    // Check if server has cached key material
    char server_response[MAXLINE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    int recv_len = recvfrom(sockfd, server_response, sizeof(server_response), 0,(struct sockaddr *)&from_addr, &from_len);
    if (recv_len < 0) {
        perror("recvfrom()");
        goto cleanup;
    }
    
    server_response[recv_len] = '\0';
    
    if (strncmp(server_response, "yes", 3) == 0) {
        printf("Server has cached key material. Loading from file...\n");
        
        char filename[256];
        snprintf(filename, sizeof(filename), "client_keys/aes_key_%s.txt",argv[1]);
        FILE *key_file = fopen(filename, "r");
        if (key_file == NULL) {
            fprintf(stderr, "Could not open aes_key file. Performing full handshake.\n");
            goto full_hs;
        }
        
        char hex_key[65];
        if (fscanf(key_file, "%64s", hex_key) != 1) {
            fprintf(stderr, "Failed to read key from file\n");
            fclose(key_file);
            goto full_hs;
        }
        fclose(key_file);
        
        // Convert hex string to bytes
        for (unsigned int i = 0; i < 32; i++) {
            sscanf(&hex_key[i * 2], "%2hhx", &key_material[i]);
        }
        
        printf("Session resumed! Using cached key. No handshake required.\n\n");
        
        // printf("Shared Secret (32 bytes for AES-256-CTR): ");
        // for (unsigned int i = 0; i < sizeof(key_material); i++) {
        //     printf("%02x", key_material[i]);
        // }
        // printf("\n\n");

        // Setup fresh AES with zero IV for this session
        Aes aes_enc, aes_dec;
        unsigned char iv_enc[AES_BLOCK_SIZE];
        unsigned char iv_dec[AES_BLOCK_SIZE];
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

        // Communication loop without SSL - direct UDP with AES
        while (1) {
            if (fgets(sendLine, MAXLINE, stdin) == NULL)
                break;

            if (strncmp(sendLine, "exit", 4) == 0) {
                sendto(sockfd, "", 0, 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
                break;
            }

            int msgLen = strlen(sendLine);
            unsigned char encrypted[MAXLINE];

            if (wc_AesCtrEncrypt(&aes_enc, encrypted, (unsigned char *)sendLine, msgLen) != 0) {
                fprintf(stderr, "AES encryption failed\n");
                goto cleanup;
            }

            printf("[Encrypted %d bytes]\n", msgLen);

            // Send directly via UDP (no SSL)
            if (sendto(sockfd, encrypted, msgLen, 0, (struct sockaddr *)&servAddr, sizeof(servAddr)) != msgLen) {
                perror("sendto()");
                goto cleanup;
            }

            // Receive directly via UDP (no SSL)
            struct sockaddr_in recv_addr;
            socklen_t recv_len = sizeof(recv_addr);
            n = recvfrom(sockfd, recvLine, sizeof(recvLine) - 1, 0, (struct sockaddr *)&recv_addr, &recv_len);

            if (n > 0) {
                unsigned char decrypted[MAXLINE];
                if (wc_AesCtrEncrypt(&aes_dec, decrypted, (unsigned char *)recvLine, n) != 0) {
                    fprintf(stderr, "AES decryption failed\n");
                    goto cleanup;
                }

                decrypted[n] = '\0';
                printf("%s[Decrypted %d bytes]\n\n", decrypted, n);
            } else {
                perror("recvfrom()");
                goto cleanup;
            }
        }

        exitVal = 0;
        return exitVal;
    }

    printf("Server requires full handshake.\n");

full_hs:

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS)
    {
        err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "err = %d, %s\n", err, wolfSSL_ERR_reason_error_string(err));
        fprintf(stderr, "wolfSSL_connect failed\n");
        goto cleanup;
    }

    show_conn_info(ssl);

    const char *label = "EXPORTER-key-for-aes-ctr";

    ret = wolfSSL_export_keying_material(ssl, key_material, sizeof(key_material),label, strlen(label), NULL, 0, 0);
    if (ret != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "Failed to export keying material\n");
        goto cleanup;
    }

    printf("\nExtracted Shared Secret from ML-KEM Key Exchange\n\n");
    skip_hs:
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
        if (fgets(sendLine, MAXLINE, stdin) == NULL)
            break;

        if (strncmp(sendLine, "exit", 4) == 0)
        {
            break;
        }

        int msgLen = strlen(sendLine);
        unsigned char encrypted[MAXLINE];

        if (wc_AesCtrEncrypt(&aes_enc, encrypted, (unsigned char *)sendLine, msgLen) != 0)
        {
            fprintf(stderr, "AES encryption failed\n");
            goto cleanup;
        }

        printf("[Encrypted %d bytes] \n", msgLen);

        if (wolfSSL_write(ssl, encrypted, msgLen) != msgLen)
        {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err,
                    wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_write failed\n");
            goto cleanup;
        }

        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine) - 1);

        if (n > 0)
        {
            unsigned char decrypted[MAXLINE];
            if (wc_AesCtrEncrypt(&aes_dec, decrypted, (unsigned char *)recvLine, n) != 0)
            {
                fprintf(stderr, "AES decryption failed\n");
                goto cleanup;
            }

            decrypted[n] = '\0';
            printf("%s[Decrypted %d bytes]\n\n", decrypted, n);
        }
        else
        {
            err = wolfSSL_get_error(ssl, 0);
            fprintf(stderr, "err = %d, %s\n", err,
                    wolfSSL_ERR_reason_error_string(err));
            fprintf(stderr, "wolfSSL_read failed\n");
            goto cleanup;
        }
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "client_keys/aes_key_%s.txt",argv[1]);

    FILE *key_file = fopen(filename, "w");
    if (key_file != NULL) {
        for (unsigned int i=0;i<sizeof(key_material);i++) {
            fprintf(key_file,"%02x",key_material[i]);
        }
        fprintf(key_file,"\n");
        fclose(key_file);
        printf("Key material saved to aes_key.txt\n");
    } 
    else {
        perror("Failed to write key file");
    }

    exitVal = 0;

cleanup:
    if (ssl != NULL)
    {
        ret = wolfSSL_shutdown(ssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
            ret = wolfSSL_shutdown(ssl);
        if (ret != WOLFSSL_SUCCESS)
        {
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
