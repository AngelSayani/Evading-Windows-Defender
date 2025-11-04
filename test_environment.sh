#!/bin/bash
# Test environment script for Kali system
echo "=== Environment Test - Kali Attacker System ==="

echo "[*] Checking Metasploit..."
if command -v msfvenom &> /dev/null; then
    echo "    [+] msfvenom installed: $(msfvenom --version | head -1)"
    echo "    [+] msfconsole available"
else
    echo "    [-] msfvenom not found"
fi

echo "[*] Checking Python..."
if command -v python3 &> /dev/null; then
    echo "    [+] Python3 installed: $(python3 --version)"
else
    echo "    [-] Python3 not found"
fi

echo "[*] Checking lab files..."
if [ -d "/home/kali/evasion_lab" ]; then
    echo "    [+] Lab files present in /home/kali/evasion_lab"
    echo "    Shell scripts: $(ls -1 /home/kali/evasion_lab/*.sh 2>/dev/null | wc -l)"
    echo "    Python scripts: $(ls -1 /home/kali/evasion_lab/*.py 2>/dev/null | wc -l)"
    echo "    PowerShell scripts: $(ls -1 /home/kali/evasion_lab/*.ps1 2>/dev/null | wc -l)"
else
    echo "    [-] Lab files missing"
fi

echo "[*] Checking working directory..."
if [ -d "/home/kali/payloads" ]; then
    echo "    [+] Payloads directory exists"
    echo "    Files: $(ls -1 /home/kali/payloads/ 2>/dev/null | wc -l)"
else
    echo "    [-] Payloads directory missing"
fi

echo "[*] Checking network..."
ip_addr=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ ! -z "$ip_addr" ]; then
    echo "    [+] Kali IP address: $ip_addr"
    echo "    [!] Windows target should be able to reach this IP"
else
    echo "    [-] Could not determine IP address"
fi

echo ""
echo "[+] Environment test complete"
echo "[*] Ready to begin evasion lab!"
