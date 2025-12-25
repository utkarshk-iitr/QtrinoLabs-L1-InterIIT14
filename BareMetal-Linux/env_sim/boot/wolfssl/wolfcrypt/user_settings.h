#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/*=============================================================================
 * System Type Definitions (must come first)
 *============================================================================*/
#include <sys/types.h>  /* For ssize_t needed by wolfio.h */

/*=============================================================================
 * Bare-metal / No-OS Settings
 *============================================================================*/
#define NO_FILESYSTEM               /* No filesystem support */
#define NO_WOLFSSL_DIR              /* No directory access */
#define SINGLE_THREADED             /* No threading support */
#define NO_WRITEV                   /* No writev() support */
#define WOLFSSL_NO_SOCK             /* No socket support - using custom IO */
#define WOLFSSL_USER_IO             /* Use custom IO callbacks */

/*=============================================================================
 * Time / Clock Settings
 *============================================================================*/
#define NO_TIME_H
#define WOLFSSL_NO_CLOCK
#define NO_ASN_TIME
#define USER_TIME                   /* User-provided time functions */

/*=============================================================================
 * Math Backend
 *============================================================================*/
#define WOLFSSL_SP_MATH_ALL         /* Use SP math for all operations */
#define WOLFSSL_SP_SMALL            /* Smaller SP code (trades speed for size) */

/*=============================================================================
 * Memory Optimization
 *============================================================================*/
#define WOLFSSL_USE_ALIGN          /* Avoid unaligned word accesses on RISC-V */
#define WOLFSSL_SMALL_STACK         /* Optimize for small stack usage */
#define WOLFSSL_SMALL_CERT_VERIFY   /* Lower memory certificate verification */
#define WOLFSSL_SMALL_SESSION_CACHE /* Smaller session cache */

/*=============================================================================
 * TLS / DTLS Protocol Settings
 *============================================================================*/
#define WOLFSSL_DTLS                /* Enable DTLS support */
#define WOLFSSL_DTLS13              /* Enable DTLS 1.3 */
#define WOLFSSL_TLS13               /* Enable TLS 1.3 (required for DTLS 1.3) */
#define WOLFSSL_DTLS_MTU            /* Track MTU for proper fragmentation/ACK */
#define WOLFSSL_DTLS_CH_FRAG        /* Allow ClientHello fragmentation for PQ */
#define HAVE_TLS_EXTENSIONS         /* TLS extensions support */
#define HAVE_SUPPORTED_CURVES       /* Supported curves extension */
#define HAVE_EXTENDED_MASTER        /* Extended master secret */
#define NO_OLD_TLS                  /* Disable old TLS versions */
#define NO_WOLFSSL_SERVER           /* Client only, no server support */

#define WOLFSSL_W64_WRAPPER         /* 64-bit wrapper for DTLS 1.3 sequence numbers */
#define WOLFSSL_DTLS_CID            /* DTLS Connection ID support */
#define WOLFSSL_SEND_HRR_COOKIE     /* Handle HelloRetryRequest cookie from server */
#define HAVE_SESSION_TICKET         /* Session ticket support for TLS 1.3 */

/* Enable proactive ACK sending for fragmented PQ handshakes */
#define WOLFSSL_DTLS13_SEND_MOREACK_DEFAULT 1

/*=============================================================================
 * Cryptographic Algorithm Support
 *============================================================================*/
/* Hash algorithms */
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3                /* Required for ML-KEM/ML-DSA */
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128

/* Symmetric encryption */
#define HAVE_AESGCM                 /* AES-GCM for DTLS */
#define HAVE_AEAD                   /* AEAD support required for TLS 1.3 */
#define GCM_SMALL                   /* Smaller GCM implementation */
#define NO_DES3                     /* Disable DES3 */
#define NO_RC4                      /* Disable RC4 */
#define NO_MD4                      /* Disable MD4 */
#define NO_DH                       /* Disable DH */

/* Asymmetric algorithms */
#define HAVE_ECC                    /* Enable ECC */
#define ECC_TIMING_RESISTANT        /* ECC timing resistance */
#define HAVE_ECC256                 /* secp256r1 support */
#define HAVE_X25519                 /* X25519 key exchange */
#define HAVE_CURVE25519
#define HAVE_ED25519                /* ED25519 signatures */

/* RSA support (may be needed for some cert chains) */
#define HAVE_RSA
#define WC_RSA_BLINDING             /* RSA blinding for security */
#define WC_RSA_PSS                  /* RSA-PSS for TLS 1.3 */
#define WOLFSSL_KEY_GEN
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC

/*=============================================================================
 * Post-Quantum Cryptography (ML-KEM / ML-DSA)
 *============================================================================*/
/* ML-KEM (Kyber) Key Encapsulation */
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_KYBER          /* Enable ML-KEM in wolfSSL TLS */
#define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
#define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM

/* ML-DSA (Dilithium) Digital Signatures */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_NO_MAKE_KEY  /* Don't need key generation on client */
#define WOLFSSL_DILITHIUM_SMALL        /* Smaller implementation */

/*=============================================================================
 * Key Derivation
 *============================================================================*/
#define HAVE_HKDF                   /* HKDF for TLS 1.3 key derivation */

/*=============================================================================
 * Certificate Settings
 *============================================================================*/
#define WOLFSSL_ASN_TEMPLATE        /* Use ASN template code */
#define WOLFSSL_BASE64_ENCODE       /* Base64 encoding support */

/*=============================================================================
 * Debugging (comment out for production)
 *============================================================================*/
#define DEBUG_WOLFSSL
#define WOLFSSL_DEBUG_TLS
#define SHOW_GEN

/*=============================================================================
 * Custom RNG Seed Function
 *============================================================================*/
extern int CustomRngGenerateBlock(unsigned char *, unsigned int);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

/*=============================================================================
 * Disable Unused Features
 *============================================================================*/
#define NO_DSA                      /* Disable DSA */
#define NO_PSK                      /* Disable PSK */
#define NO_PWDBASED                 /* Disable password-based crypto */
/* #define NO_SESSION_CACHE */      /* Uncomment if session cache not needed */
/* #define NO_ERROR_STRINGS */      /* Uncomment for production to save space */

#endif /* USER_SETTINGS_H */