# Test script to verify evasion
param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadPath
)

Write-Host "=== Testing Payload Evasion ===" -ForegroundColor Cyan
Write-Host "Payload: $PayloadPath"

# Check if Defender is monitoring
$defender = Get-MpComputerStatus
if (-not $defender.RealTimeProtectionEnabled) {
    Write-Host "WARNING: Real-time protection is disabled!" -ForegroundColor Yellow
}

Write-Host "`n[*] Executing payload..." -ForegroundColor Green

try {
    # Execute the payload
    & $PayloadPath
    
    Write-Host "[+] Payload executed without detection!" -ForegroundColor Green
    
    # Wait and check for detection
    Start-Sleep -Seconds 5
    
    $recentThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue | 
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-1) }
    
    if ($recentThreats) {
        Write-Host "[-] Threat detected by Defender!" -ForegroundColor Red
        $recentThreats | ForEach-Object {
            Write-Host "   Threat: $($_.ThreatName)"
        }
    } else {
        Write-Host "[+] No detection after execution!" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[-] Execution blocked or failed!" -ForegroundColor Red
    Write-Host "   Error: $_" -ForegroundColor Red
}
