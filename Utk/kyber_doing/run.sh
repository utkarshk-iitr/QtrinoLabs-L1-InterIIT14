gcc -std=c11 -DWOLFSSL_MLKEM_KYBER client_dtls.c -o client_dtls -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs -lpthread
gcc -std=c11 -DWOLFSSL_MLKEM_KYBER server_dtls.c -o server_dtls -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs -lpthread
