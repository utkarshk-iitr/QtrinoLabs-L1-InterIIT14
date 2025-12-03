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
#include <time.h>

#define MAXLINE 4096
#define INITIAL_TABLE_SIZE 16
#define MAX_LOAD_FACTOR 0.75
#define CACHE_EXPIRY_SECONDS 10

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

typedef struct KeyCacheEntry {
    char ip_port[22];
    unsigned char key_material[32];
    time_t expiration_time;
    int occupied;
} KeyCacheEntry;

typedef struct SecondLevelTable {
    KeyCacheEntry *entries;
    size_t size;
    unsigned int a, b;
} SecondLevelTable;

typedef struct DynamicPerfectHash {
    SecondLevelTable *buckets;
    size_t primary_size;
    size_t num_elements;
    unsigned int a, b; 
    unsigned int prime;
} DynamicPerfectHash;

static DynamicPerfectHash *cache = NULL;
#define HASH_PRIME 15485863

static unsigned int universal_hash(const char *key, unsigned int a, unsigned int b, 
                                   unsigned int prime, size_t table_size) {
    unsigned int hash_val = 0;
    for (size_t i = 0; key[i] != '\0'; i++) {
        hash_val = (hash_val * 31 + (unsigned char)key[i]) % prime;
    }
    return ((a * hash_val + b) % prime) % table_size;
}

static void generate_hash_params(unsigned int *a, unsigned int *b, unsigned int prime) {
    *a = (rand() % (prime - 1)) + 1;
    *b = rand() % prime;
}

static int init_second_level_table(SecondLevelTable *table, KeyCacheEntry *entries, size_t num_entries) {
    if (num_entries == 0) {
        table->entries = NULL;
        table->size = 0;
        return 1;
    }

    table->size = num_entries * num_entries;
    if (table->size == 0) table->size = 1;
    
    table->entries = calloc(table->size, sizeof(KeyCacheEntry));
    if (!table->entries) {
        return 0;
    }

    int max_attempts = 100;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        generate_hash_params(&table->a, &table->b, HASH_PRIME);
        
        for (size_t i = 0; i < table->size; i++) {
            table->entries[i].occupied = 0;
        }

        int collision = 0;
        for (size_t i = 0; i < num_entries; i++) {
            unsigned int idx = universal_hash(entries[i].ip_port, table->a, table->b, HASH_PRIME, table->size);
            
            if (table->entries[idx].occupied) {
                collision = 1;
                break;
            }
            
            table->entries[idx] = entries[i];
            table->entries[idx].occupied = 1;
        }

        if (!collision) {
            return 1;
        }
    }

    generate_hash_params(&table->a, &table->b, HASH_PRIME);
    for (size_t i = 0; i < table->size; i++) {
        table->entries[i].occupied = 0;
    }

    for (size_t i = 0; i < num_entries; i++) {
        unsigned int idx = universal_hash(entries[i].ip_port, table->a, table->b, HASH_PRIME, table->size);
        
        while (table->entries[idx].occupied) {
            idx = (idx + 1) % table->size;
        }
        
        table->entries[idx] = entries[i];
        table->entries[idx].occupied = 1;
    }

    return 1;
}

static DynamicPerfectHash* dph_create(size_t initial_size) {
    DynamicPerfectHash *hash = malloc(sizeof(DynamicPerfectHash));
    if (!hash) return NULL;

    hash->primary_size = initial_size;
    hash->num_elements = 0;
    hash->prime = HASH_PRIME;
    
    srand(time(NULL));
    generate_hash_params(&hash->a, &hash->b, hash->prime);

    hash->buckets = calloc(hash->primary_size, sizeof(SecondLevelTable));
    if (!hash->buckets) {
        free(hash);
        return NULL;
    }

    return hash;
}

static int dph_rehash(DynamicPerfectHash *hash) {
    size_t new_size = hash->primary_size * 2;
    
    KeyCacheEntry *all_entries = malloc(hash->num_elements * sizeof(KeyCacheEntry));
    if (!all_entries) return 0;

    size_t count = 0;
    for (size_t i = 0; i < hash->primary_size; i++) {
        SecondLevelTable *bucket = &hash->buckets[i];
        if (bucket->entries) {
            for (size_t j = 0; j < bucket->size; j++) {
                if (bucket->entries[j].occupied) {
                    all_entries[count++] = bucket->entries[j];
                }
            }
            free(bucket->entries);
        }
    }

    free(hash->buckets);

    hash->primary_size = new_size;
    hash->buckets = calloc(new_size, sizeof(SecondLevelTable));
    if (!hash->buckets) {
        free(all_entries);
        return 0;
    }

    generate_hash_params(&hash->a, &hash->b, hash->prime);

    for (size_t i = 0; i < count; i++) {
        unsigned int idx = universal_hash(all_entries[i].ip_port, hash->a, hash->b, hash->prime, hash->primary_size);
        
        SecondLevelTable *bucket = &hash->buckets[idx];
        size_t bucket_count = 0;
        for (size_t j = 0; j < count; j++) {
            unsigned int test_idx = universal_hash(all_entries[j].ip_port, hash->a, hash->b,
                                                   hash->prime, hash->primary_size);
            if (test_idx == idx) {
                bucket_count++;
            }
        }

        if (bucket_count > 0 && !bucket->entries) {
            KeyCacheEntry *bucket_entries = malloc(bucket_count * sizeof(KeyCacheEntry));
            size_t pos = 0;
            for (size_t j = 0; j < count; j++) {
                unsigned int test_idx = universal_hash(all_entries[j].ip_port, hash->a, hash->b,
                                                       hash->prime, hash->primary_size);
                if (test_idx == idx) {
                    bucket_entries[pos++] = all_entries[j];
                }
            }
            init_second_level_table(bucket, bucket_entries, bucket_count);
            free(bucket_entries);
        }
    }

    free(all_entries);
    return 1;
}

static int dph_insert(DynamicPerfectHash *hash, const char *key, const unsigned char *value, time_t expiry) {
    double load_factor = (double)hash->num_elements / hash->primary_size;
    if (load_factor > MAX_LOAD_FACTOR) {
        if (!dph_rehash(hash)) {
            return 0;
        }
    }

    unsigned int idx = universal_hash(key, hash->a, hash->b, hash->prime, hash->primary_size);
    SecondLevelTable *bucket = &hash->buckets[idx];

    if (bucket->entries) {
        for (size_t i = 0; i < bucket->size; i++) {
            if (bucket->entries[i].occupied && 
                strcmp(bucket->entries[i].ip_port, key) == 0) {
                // Update existing entry with new key and expiration time
                memcpy(bucket->entries[i].key_material, value, 32);
                bucket->entries[i].expiration_time = expiry;
                // printf("Updated cache entry for %s (new expiration time: %ld)\n", key, expiry);
                return 1;
            }
        }
    }

    size_t old_count = 0;
    KeyCacheEntry *old_entries = NULL;
    
    if (bucket->entries) {
        for (size_t i = 0; i < bucket->size; i++) {
            if (bucket->entries[i].occupied) {
                old_count++;
            }
        }
        
        if (old_count > 0) {
            old_entries = malloc(old_count * sizeof(KeyCacheEntry));
            size_t pos = 0;
            for (size_t i = 0; i < bucket->size; i++) {
                if (bucket->entries[i].occupied) {
                    old_entries[pos++] = bucket->entries[i];
                }
            }
        }
        free(bucket->entries);
        bucket->entries = NULL;
    }

    KeyCacheEntry *new_entries = malloc((old_count + 1) * sizeof(KeyCacheEntry));
    for (size_t i = 0; i < old_count; i++) {
        new_entries[i] = old_entries[i];
    }
    
    strncpy(new_entries[old_count].ip_port, key, sizeof(new_entries[old_count].ip_port) - 1);
    new_entries[old_count].ip_port[sizeof(new_entries[old_count].ip_port) - 1] = '\0';
    memcpy(new_entries[old_count].key_material, value, 32);
    new_entries[old_count].expiration_time = expiry;
    new_entries[old_count].occupied = 1;
    // printf("Inserted new cache entry for %s (expiration time: %ld)\n", key, expiry);

    int success = init_second_level_table(bucket, new_entries, old_count + 1);
    
    free(new_entries);
    if (old_entries) free(old_entries);

    if (success) {
        hash->num_elements++;
        return 1;
    }
    
    return 0;
}

static int dph_lookup(DynamicPerfectHash *hash, const char *key, unsigned char *value, int *expired) {
    unsigned int idx = universal_hash(key, hash->a, hash->b, hash->prime, hash->primary_size);
    SecondLevelTable *bucket = &hash->buckets[idx];

    *expired = 0;

    if (!bucket->entries) {
        return 0;
    }

    time_t current_time = time(NULL);

    for (size_t i = 0; i < bucket->size; i++) {
        if (bucket->entries[i].occupied && 
            strcmp(bucket->entries[i].ip_port, key) == 0) {
            
            // Check if entry has expired (lazy expiration)
            if (current_time >= bucket->entries[i].expiration_time) {
                // printf("Cache entry EXPIRED for %s (expiration time: %ld, current time: %ld)\n", 
                //        key, bucket->entries[i].expiration_time, current_time);
                *expired = 1;
                return 1;  // Found but expired
            }
            
            // Entry is valid and not expired
            // printf("Cache HIT for %s (expiration time: %ld, current time: %ld)\n", 
            //        key, bucket->entries[i].expiration_time, current_time);
            memcpy(value, bucket->entries[i].key_material, 32);
            return 1;
        }
    }

    // printf("Cache MISS for %s (no entry found)\n", key);
    return 0;
}

static void dph_destroy(DynamicPerfectHash *hash) {
    if (!hash) return;

    for (size_t i = 0; i < hash->primary_size; i++) {
        if (hash->buckets[i].entries) {
            free(hash->buckets[i].entries);
        }
    }
    free(hash->buckets);
    free(hash);
}

static void cache_store(const struct sockaddr_in *addr, const unsigned char *material) {
    char key[22];
    snprintf(key, sizeof(key), "%s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    
    if (!cache) {
        cache = dph_create(INITIAL_TABLE_SIZE);
        if (!cache) {
            fprintf(stderr, "Failed to create cache\n");
            return;
        }
    }
    
    time_t expiration = time(NULL) + CACHE_EXPIRY_SECONDS;
    dph_insert(cache, key, material, expiration);
}

static int cache_lookup(const struct sockaddr_in *addr, unsigned char *material, int *expired) {
    if (!cache) {
        return 0;
    }

    char key[22];
    snprintf(key, sizeof(key), "%s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    
    return dph_lookup(cache, key, material, expired);
}

static void cache_clear(void) {
    if (cache) {
        dph_destroy(cache);
        cache = NULL;
    }
}

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

    // Add socket reuse option
    int optval = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR)");
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
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue; // Interrupted or would block, try again
            }
            perror("recvfrom()");
            goto cleanup;
        }
        else if (ret == 0)
        {
            fprintf(stderr, "recvfrom zero return\n");
            continue;
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
        printf("Client connected from %s:%d\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
        unsigned char key_material[32];
        int is_expired = 0;

        if(cache_lookup(&cliaddr, key_material, &is_expired) && !is_expired){
            printf("Session resumed! Using cached key\n");
            char resume_msg[] = "yes";
            if (sendto(listenfd, resume_msg, sizeof(resume_msg), 0, (struct sockaddr *)&cliaddr, cliLen) < 0) {
                perror("Failed to send resume confirmation");
                goto cleanup;
            }

            // printf("Shared Secret (32 bytes for AES-256-CTR): ");
            // for (unsigned int i = 0; i < sizeof(key_material); i++) {
            //     printf("%02x", key_material[i]);
            // }
            // printf("\n\n");
            
            // Setup AES directly without SSL handshake
            Aes aes_enc, aes_dec;
            unsigned char iv_enc[AES_BLOCK_SIZE];
            unsigned char iv_dec[AES_BLOCK_SIZE];
            memset(iv_enc, 0, AES_BLOCK_SIZE);
            memset(iv_dec, 0, AES_BLOCK_SIZE);

            if (wc_AesSetKey(&aes_enc, key_material, sizeof(key_material), iv_enc, AES_ENCRYPTION) != 0) {
                fprintf(stderr, "Failed to set AES encryption key\n");
                wolfSSL_free(ssl);
                ssl = NULL;
                continue;
            }

            if (wc_AesSetKey(&aes_dec, key_material, sizeof(key_material), iv_dec, AES_ENCRYPTION) != 0) {
                fprintf(stderr, "Failed to set AES decryption key\n");
                wolfSSL_free(ssl);
                ssl = NULL;
                continue;
            }

            // Consume the initial 1-byte packet that was used to trigger MSG_PEEK
            char initial_byte[1];
            socklen_t initial_cliLen = sizeof(cliaddr);
            recvfrom(listenfd, initial_byte, sizeof(initial_byte), 0, 
                    (struct sockaddr *)&cliaddr, &initial_cliLen);

            // Communication loop without SSL - direct UDP with AES
            while (1) {
                socklen_t recv_cliLen = sizeof(cliaddr);
                recvLen = recvfrom(listenfd, buff, sizeof(buff) - 1, 0, 
                                  (struct sockaddr *)&cliaddr, &recv_cliLen);
                
                if (recvLen > 0) {
                    unsigned char decrypted[MAXLINE];

                    if (wc_AesCtrEncrypt(&aes_dec, decrypted, (unsigned char *)buff, recvLen) != 0) {
                        fprintf(stderr, "AES decryption failed\n");
                        break;
                    }

                    decrypted[recvLen] = '\0';
                    printf("\nDecrypted: %s[Decrypted %d bytes]\n", decrypted, recvLen);

                    unsigned char encrypted_ack[MAXLINE];
                    if (wc_AesCtrEncrypt(&aes_enc, encrypted_ack, (unsigned char *)ack, sizeof(ack)) != 0) {
                        fprintf(stderr, "AES encryption failed\n");
                        break;
                    }

                    printf("Sending encrypted ACK\n");
                    if (sendto(listenfd, encrypted_ack, sizeof(ack), 0, 
                              (struct sockaddr *)&cliaddr, recv_cliLen) < 0) {
                        perror("sendto failed");
                        break;
                    }
                } else if (recvLen < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    perror("recvfrom");
                    break;
                }
                else{
                    printf("Client disconnected from resumed session.\n");
                    break;
                }
            }

            wolfSSL_free(ssl);
            ssl = NULL;
            
            // Clear any remaining data
            char discard[MAXLINE];
            while (recvfrom(listenfd, discard, sizeof(discard), MSG_DONTWAIT, 
                           (struct sockaddr *)&cliaddr, &cliLen) > 0) {
            }
            
            printf("\nClient disconnected. Awaiting new connection...\n");
            continue;
        }

        // Cache entry either doesn't exist or is expired - perform full handshake
        if (is_expired) {
            printf("Cache entry expired! Performing full handshake and updating cache...\n");
        } else {
            printf("No cache entry found! Performing full handshake...\n");
        }

        char handshake_msg[] = "no";
        if (sendto(listenfd, handshake_msg, sizeof(handshake_msg), 0,(struct sockaddr *)&cliaddr, cliLen) < 0) {
            perror("Failed to send handshake message");
            goto cleanup;
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

        const char *label = "EXPORTER-key-for-aes-ctr";

        ret = wolfSSL_export_keying_material(ssl, key_material, sizeof(key_material),label, strlen(label), NULL, 0, 0);
        if (ret != WOLFSSL_SUCCESS)
        {
            fprintf(stderr, "Failed to export keying material\n");
            goto cleanup;
        }
        
        cache_store(&cliaddr, key_material);
        printf("\nExtracted Shared Secret from ML-KEM Key Exchange\n");
        key_exc:
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

        // Clear any remaining data from the disconnected client
        char discard[MAXLINE];
        while (recvfrom(listenfd, discard, sizeof(discard), MSG_DONTWAIT, 
                       (struct sockaddr *)&cliaddr, &cliLen) > 0) {
            // Drain the socket
        }

        printf("\nClient disconnected. Awaiting new connection...\n");
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

    if(cache != NULL) {
        cache_clear();
    }
}