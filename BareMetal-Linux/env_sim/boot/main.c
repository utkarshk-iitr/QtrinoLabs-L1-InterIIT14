#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <irq.h>
#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>

#include "dtls_client.h"
#include "certs_buffer.h"
#include "liteeth_udp.h"

static const uint8_t my_mac[6] = {0xaa, 0xb6, 0x24, 0x69, 0x77, 0x21};
#define MY_IP       IPTOINT(192, 168, 1, 50)
#define SERVER_IP   IPTOINT(192, 168, 1, 100)
#define SERVER_PORT 23456

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#include <wolfssl/wolfcrypt/types.h>

int CustomRngGenerateBlock(byte *output, word32 sz) {
    for (word32 i = 0; i < sz; i++) {
        output[i] = (byte)(i * 37 + 123); // placeholder (NOT SECURE!)
    }
    return 0;
}

#include <sys/time.h>
#include <time.h>

int gettimeofday(struct timeval* tv, void* tz) {
    (void)tz;
    if (tv) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}


/* Read a line from UART with echo, returns length (excluding null terminator) */
static int read_line(char* buf, int maxlen) {
    int i = 0;
    char c;
    
    while (i < maxlen - 1) {
        /* Wait for character */
        while (!uart_read_nonblock()) {
            /* Could add a small delay or service network here */
        }
        c = uart_read();
        
        /* Handle backspace */
        if (c == '\b' || c == 127) {
            if (i > 0) {
                i--;
                printf("\b \b");  /* Erase character on terminal */
            }
            continue;
        }
        
        /* Handle enter (CR or LF) */
        if (c == '\r' || c == '\n') {
            printf("\n");
            buf[i] = '\0';
            return i;
        }
        
        /* Echo and store printable characters */
        if (c >= 32 && c < 127) {
            buf[i++] = c;
            printf("%c", c);
        }
    }
    
    buf[i] = '\0';
    return i;
}

static int run_dtls_client_demo(void) {
    dtls_client_t client;
    dtls_client_config_t config;
    int ret;
    
    char send_buf[256];
    uint8_t recv_buf[256];
    int recv_len;
    int send_len;
    
    printf("\n");
    printf("=== demo dtls-pqc initiated ===\n");
    
    dtls_client_config_init(&config);
    dtls_client_config_set_server(&config, SERVER_IP, SERVER_PORT);
    size_t ca_len;
    const uint8_t* ca_cert = get_ca_cert_buffer(&ca_len);
    dtls_client_config_set_ca_cert(&config, ca_cert, ca_len);
    
    config.verify_peer = 1;  
    
    printf("[MAIN] Initializing DTLS client...\n");
    printf("       Server: " IP_FMT ":%d\n", IP_ARGS(SERVER_IP), SERVER_PORT);
    
    ret = dtls_client_init(&client, &config);
    if (ret != 0) {
        printf("[MAIN] Failed to initialize DTLS client: %d\n", ret);
        return -1;
    }
    
    printf("[MAIN] Connecting to server...\n");
    
    ret = dtls_client_connect(&client);
    if (ret != 0) {
        printf("[MAIN] Failed to connect: %d\n", ret);
        dtls_client_cleanup(&client);
        return -1;
    }
    
    printf("[MAIN] Connected successfully!\n");
    printf("[MAIN] Type messages to send (type 'exit' to quit):\n");
    printf(">> ");
    
    /* Interactive message loop */
    while (1) {
        /* Read a line from UART */
        send_len = read_line(send_buf, sizeof(send_buf) - 1);
        
        /* Check for exit command */
        if (send_len >= 4 && strncmp(send_buf, "exit", 4) == 0) {
            printf("[MAIN] Exiting...\n");
            break;
        }
        
        /* Skip empty lines */
        if (send_len == 0) {
            printf(">> ");
            continue;
        }
        
        /* Add newline for server compatibility */
        send_buf[send_len] = '\n';
        send_buf[send_len + 1] = '\0';
        send_len++;
        
        /* Send message */
        printf("[MAIN] Sending: %s", send_buf);
        ret = dtls_client_send(&client, (const uint8_t*)send_buf, send_len);
        if (ret < 0) {
            printf("[MAIN] Send failed: %d\n", ret);
            break;
        }
        printf("[MAIN] Sent %d bytes\n", ret);
        
        /* Wait for response */
        printf("[MAIN] Waiting for response...\n");
        recv_len = dtls_client_recv(&client, recv_buf, sizeof(recv_buf) - 1);
        if (recv_len > 0) {
            recv_buf[recv_len] = '\0';
            printf("[MAIN] Server: %s", recv_buf);
        } else if (recv_len == 0) {
            printf("[MAIN] No response received\n");
        } else {
            printf("[MAIN] Receive error: %d\n", recv_len);
            break;
        }
        
        printf(">> ");
    }
    
    printf("[MAIN] Disconnecting...\n");
    dtls_client_disconnect(&client);
    dtls_client_cleanup(&client);
    
    printf("=== demo done ===\n");
    
    return 0;
}

int main(void) {
    int ret;
    
#ifdef CONFIG_CPU_HAS_INTERRUPT
    irq_setmask(0);
    irq_setie(1);
#endif
    
    uart_init();
    
    printf("\n");
    printf("=== main entering ===\n");
    
    ret = dtls_client_init_system(my_mac, MY_IP);
    if (ret != 0) {
        printf("[MAIN] System initialization failed: %d\n", ret);
        return -1;
    }
    
    printf("[MAIN] System initialized\n");
    printf("       Local IP: " IP_FMT "\n", IP_ARGS(MY_IP));
    
    
    run_dtls_client_demo();
    dtls_client_cleanup_system();
    
    printf("=== main exit ===\n");
    
    return 0;
}






//     
//     // sdcard_init();
    // spisdcard_init();
//     printf("sdcard_init() done\n");

//     
    // fatfs_set_ops_spisdcard();
//     printf("fatfs_set_ops_sdcard() done\n");
    
//     
//     FRESULT fr = f_mount(&fs, "", 1);  //MS-DOS partition table + FAT32 Filesystem
//     printf("f_mount -> %d\n", fr);
//     if (fr != FR_OK) {
//         printf("mount failed\n");
//         return 1;
//     }

//     FIL file;
//     UINT bytes=0;

//     
//     printf("\n[PHASE 1] Opening test.txt for READ...\n");
//     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
//     printf("[PHASE 1] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     static char buf[4096];
//     memset(buf, 0, sizeof(buf));

//     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
//     printf("[PHASE 1] f_read -> %d, bytes=%u\n", fr, bytes);
//     printf("[PHASE 1] Contents BEFORE write:\n%s\n", buf);

//     f_close(&file);
//     bytes=0;

//     
//     printf("\n[PHASE 2] Opening test.txt for WRITE + TRUNCATE...\n");
//     fr = f_open(&file, "Work.txt", FA_WRITE | FA_OPEN_EXISTING);
//     printf("[PHASE 2] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     f_lseek(&file, f_size(&file));
//     // f_truncate(&file); 

//     const char *msg = "\nHELLO TO THE WORLD\n";
//     fr = f_write(&file, msg, strlen(msg), &bytes); 
//     printf("[PHASE 2] f_write -> %d, bytes=%u\n", fr, bytes);
 
//     f_close(&file);// IT FAILS HERE
//     bytes=0;

//     
//     printf("\n[PHASE 3] Opening test.txt for READ again...\n");
//     fr = f_open(&file, "Work.txt", FA_READ | FA_OPEN_EXISTING);
//     printf("[PHASE 3] f_open -> %d\n", fr);
//     if (fr != FR_OK) return 1;

//     memset(buf, 0, sizeof(buf));

//     fr = f_read(&file, buf, sizeof(buf)-1, &bytes);
//     printf("[PHASE 3] f_read -> %d, bytes=%u\n", fr, bytes);
//     printf("[PHASE 3] Contents AFTER write:\n%s\n", buf);

//     f_close(&file);

//     printf("\n=== SD TEST COMPLETE ===\n");