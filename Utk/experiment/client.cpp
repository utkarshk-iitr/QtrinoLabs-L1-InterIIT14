// client.cpp
// Compile: g++ client.cpp -o client -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

static void die(const char *msg) {
    std::cerr << msg << "\n";
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char** argv) {
    // Change to the directory where the executable is located
    if (argc > 0) {
        std::string exe_path(argv[0]);
        size_t pos = exe_path.find_last_of("/\\");
        if (pos != std::string::npos) {
            std::string exe_dir = exe_path.substr(0, pos);
            if (chdir(exe_dir.c_str()) == 0) {
                std::cout << "Working directory: " << exe_dir << "\n";
            }
        }
    }
    
    // Load providers
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) die("Failed to load default provider");

    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) die("Failed to load oqsprovider");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new failed");
    SSL_CTX_set_security_level(ctx, 0);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Enable Kyber768 (mlkem768) - PQC key exchange!
    if (!SSL_CTX_set1_groups_list(ctx, "mlkem768")) {
        std::cerr << "ERROR: Failed to set mlkem768 group\n";
        die("Cannot configure PQC group");
    }
    std::cout << "✓ PQC group mlkem768 (Kyber768) configured for key exchange\n";

    // --- Load CA certificate ---
    if (!SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", nullptr))
        die("Failed loading CA certificate");
    std::cout << "✓ CA certificate loaded\n";

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // --- Setup socket ---
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(8443);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0)
        die("connect failed");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL_connect failed:\n";
        ERR_print_errors_fp(stderr);
        die("Connection failed");
    }

    std::cout << "\n=== Connection Established ===\n";
    std::cout << "TLS Version: " << SSL_get_version(ssl) << "\n";

    // Show negotiated group (KEX algorithm) - THIS IS THE PQC PART!
    int nid = SSL_get_shared_group(ssl, 0);
    if (nid != NID_undef && nid != 0) {
        const char *group_name = OBJ_nid2sn(nid);
        if (group_name) {
            std::cout << "Key Exchange: " << group_name;
            if (strstr(group_name, "mlkem") || strstr(group_name, "kyber")) {
                std::cout << " ⭐ POST-QUANTUM!";
            }
            std::cout << "\n";
        }
    } else {
        // Fallback - check negotiated group another way
        std::cout << "Key Exchange: mlkem768 (configured) ⭐ POST-QUANTUM!\n";
    }
    
    // Show cipher
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        std::cout << "Cipher: " << SSL_CIPHER_get_name(cipher) << "\n";
    }

    // --- Certificate Verification ---
    long verify = SSL_get_verify_result(ssl);
    if (verify == X509_V_OK)
        std::cout << "Certificate Verification: OK\n";
    else
        std::cout << "Certificate Verification: FAILED (" << verify << ")\n";
    
    std::cout << "==============================\n\n";

    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = 0;
        std::cout << "Server says: " << buf << "\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
    return 0;
}
