gcc -std=c11 -DWOLFSSL_MLKEM_KYBER c_dtls.c -o clnt -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs -lpthread
gcc -std=c11 -DWOLFSSL_MLKEM_KYBER s_dtls.c -o srvr -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs
