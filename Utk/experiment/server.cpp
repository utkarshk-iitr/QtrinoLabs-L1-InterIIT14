// server.cpp
// Compile: g++ server.cpp -o server -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static void die(const char *msg) {
    std::cerr << msg << "\n";
    ERR_print_errors_fp(stderr);
    exit(1);
}

int create_server_socket(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket failed");
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) die("bind failed");
    if (listen(s, 1) < 0) die("listen failed");
    return s;
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

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new failed");
    SSL_CTX_set_security_level(ctx, 0);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Force Kyber768 KEM (mlkem768) - this is what Wireshark will show!
    if (!SSL_CTX_set1_groups_list(ctx, "mlkem768")) {
        std::cerr << "ERROR: Failed to set mlkem768 group\n";
        die("Cannot configure PQC group");
    }
    std::cout << "✓ PQC group mlkem768 (Kyber768) configured for key exchange\n";

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) != 1) {
        die("Failed loading certs/server.crt");
    }
    std::cout << "✓ Server certificate loaded\n";

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) != 1) {
        die("Failed loading certs/server.key");
    }
    std::cout << "✓ Server private key loaded\n";

    if (!SSL_CTX_check_private_key(ctx)) {
        die("Private key does not match certificate");
    }
    std::cout << "✓ Certificate and key match verified\n";

    int server_fd = create_server_socket(8443);
    std::cout << "Server started on port 8443\n";

    while (true) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL_accept failed:\n";
            ERR_print_errors_fp(stderr);
        } else {
            std::cout << "\n=== Handshake Success ===\n";
            std::cout << "TLS Version: " << SSL_get_version(ssl) << "\n";
            
            // Show negotiated group (KEX algorithm)
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
                std::cout << "Key Exchange: mlkem768 (configured) ⭐ POST-QUANTUM!\n";
            }
            
            // Show cipher
            const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
            if (cipher) {
                std::cout << "Cipher: " << SSL_CIPHER_get_name(cipher) << "\n";
            }
            std::cout << "=========================\n\n";
            
            SSL_write(ssl, "Hello from PQC server\n", 23);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
    SSL_CTX_free(ctx);
    return 0;
}
