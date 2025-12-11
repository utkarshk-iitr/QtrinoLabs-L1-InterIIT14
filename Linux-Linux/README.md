# Linux-to-Linux DTLS Client-Server Model

This directory contains a standard DTLS 1.3 (Datagram Transport Layer Security) implementation where both the client and server run on Linux systems. This setup is ideal for testing secure UDP communication, development, and understanding DTLS protocol behavior.

## Key Features

### Post-Quantum Cryptography (PQC)

This implementation includes quantum-resistant cryptographic algorithms to protect against future quantum computer attacks:

- **Kyber512 for Key Encapsulation Mechanism (KEM)**: Kyber512 is a post-quantum key exchange algorithm that provides secure key establishment resistant to attacks from quantum computers.

- **Dilithium2 (ML-DSA-44) for Digital Signatures**: Dilithium2 is a post-quantum digital signature scheme used for authentication. Also part of the CRYSTALS family, it provides strong security guarantees against quantum attacks while maintaining efficient signing and verification operations.

### Client-Based Session Resumption

The implementation includes **client-based session resumption** functionality, which allows clients to resume previously established DTLS sessions without performing a full handshake. This feature:

- Reduces latency and computational overhead on reconnection
- Improves performance for intermittent connections
- Maintains security through encrypted session tickets
- Particularly beneficial for IoT devices with power constraints

It is based on the following WolfSSL API calls:

- `wolfSSL_get1_session()` - Retrieves the current SSL/DTLS session object from an active connection.
- `wolfSSL_set_session()` - Restores a previously saved session to a new SSL/DTLS connection object before initiating a handshake.
- `wolfSSL_session_reused()` - Checks whether the current connection successfully reused a previous session.

## Components

- `server_dtls.c` - DTLS server implementation that listens for incoming connections
- `client_dtls.c` - DTLS client implementation that connects to the server
- `Makefile` - Build configuration for compiling both client and server
- `certs/` - Directory containing MLDSA44 certificates and keys for secure communication
- `wolf_setup.sh` - Setup script for installing WolfSSL dependencies

## Prerequisites

- Linux operating system (Ubuntu/Debian recommended)
- GCC compiler
- Make build system
- WolfSSL library

## Setup

1. **Install WolfSSL dependencies**:
   ```bash
   cd Linux-Linux
   chmod +x wolf_setup.sh
   ./wolf_setup.sh
   ```

2. **Build the client and server**:
   ```bash
   make
   ```
   This will compile both `server` and `client` executables.

## Running the DTLS Client-Server

### Two-Terminal Setup

1. **Terminal 1 - Start the DTLS Server**:
   ```bash
   cd Linux-Linux
   ./server <Port>
   ```
   The server will start and listen for incoming DTLS connections on the configured port.

2. **Terminal 2 - Run the DTLS Client**:
   ```bash
   cd Linux-Linux
   ./client <Server IP> <Port>
   ```
   The client will establish a secure DTLS connection with the server and begin communication.

### Expected Behavior

- The server will display connection information and incoming messages
- The client will connect, perform the DTLS handshake, and exchange encrypted data
- Both terminals will show the secure communication session details

## Cleaning Up

To remove compiled binaries:
```bash
make clean
```
