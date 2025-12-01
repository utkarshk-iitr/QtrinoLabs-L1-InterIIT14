gcc -std=c11 c_dtls.c -o clnt -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs -lpthread
gcc -std=c11 s_dtls.c -o srvr -I/usr/local/include -L/usr/local/lib -lwolfssl -loqs
