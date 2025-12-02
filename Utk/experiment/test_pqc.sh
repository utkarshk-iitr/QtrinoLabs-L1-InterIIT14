#!/bin/bash
# Complete test script for PQC TLS demo

cd /home/utk/Desktop/UtkKumar/QtrinoLabs/Utk/exp

echo "======================================"
echo "PQC TLS Test - ML-KEM-768 (Kyber768)"
echo "======================================"
echo ""

# Kill any existing server
killall server 2>/dev/null
sleep 1

# Start server
echo "[1/3] Starting server..."
./server &
SERVER_PID=$!
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "ERROR: Server failed to start!"
    exit 1
fi

echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Run client
echo "[2/3] Running client..."
echo ""
./client
echo ""

# Cleanup
echo "[3/3] Cleaning up..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "======================================"
echo "Test Complete!"
echo "======================================"
echo ""
