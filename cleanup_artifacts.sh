#!/bin/bash
# Cleanup script to remove generated payloads and artifacts

echo "=== Cleanup Script ==="
echo "[*] Removing generated payloads and artifacts..."

# Remove PowerShell payloads
if ls *.ps1 2>/dev/null | grep -q .; then
    echo "[*] Removing PowerShell payloads..."
    rm -f *.ps1
    echo "    [+] PowerShell files removed"
else
    echo "    [*] No PowerShell files to remove"
fi

# Remove Python shellcode
if [ -f "shellcode.py" ]; then
    echo "[*] Removing shellcode.py..."
    rm -f shellcode.py
    echo "    [+] Shellcode removed"
else
    echo "    [*] No shellcode.py to remove"
fi

# Remove any backup files
if ls *.bak 2>/dev/null | grep -q .; then
    echo "[*] Removing backup files..."
    rm -f *.bak
    echo "    [+] Backup files removed"
fi

# Remove temporary files
if ls /tmp/payload* 2>/dev/null | grep -q .; then
    echo "[*] Removing temporary payload files..."
    rm -f /tmp/payload*
    echo "    [+] Temporary files removed"
fi

# Kill any remaining Metasploit handlers
echo "[*] Checking for Metasploit handlers..."
if pgrep -f "msfconsole" > /dev/null; then
    echo "    [!] Killing Metasploit processes..."
    pkill -f "msfconsole"
    echo "    [+] Metasploit processes terminated"
else
    echo "    [*] No Metasploit processes running"
fi

# Clear bash history for operational security
echo "[*] Clearing command history..."
history -c
echo "    [+] Command history cleared"

echo ""
echo "=== Cleanup Complete ==="
echo "[+] All artifacts removed"
echo "[!] Remember to check Windows target for any remaining processes"
