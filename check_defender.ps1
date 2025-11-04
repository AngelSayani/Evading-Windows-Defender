# Check Windows Defender status
Write-Host "=== Windows Defender Status Check ===" -ForegroundColor Cyan

$defenderStatus = Get-MpComputerStatus

Write-Host "`nReal-time Protection: " -NoNewline
if ($defenderStatus.RealTimeProtectionEnabled) {
    Write-Host "ENABLED" -ForegroundColor Red
} else {
    Write-Host "DISABLED" -ForegroundColor Green
}

Write-Host "Behavior Monitoring: " -NoNewline
if ($defenderStatus.BehaviorMonitorEnabled) {
    Write-Host "ENABLED" -ForegroundColor Red
} else {
    Write-Host "DISABLED" -ForegroundColor Green
}

Write-Host "Anti-Spyware: " -NoNewline
if ($defenderStatus.AntispywareEnabled) {
    Write-Host "ENABLED" -ForegroundColor Red
} else {
    Write-Host "DISABLED" -ForegroundColor Green
}

Write-Host "`nLast Quick Scan: $($defenderStatus.QuickScanEndTime)"
Write-Host "Last Full Scan: $($defenderStatus.FullScanEndTime)"

# Check for recent threats
$threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 5

if ($threats) {
    Write-Host "`n=== Recent Threat Detections ===" -ForegroundColor Yellow
    $threats | ForEach-Object {
        Write-Host "Threat: $($_.ThreatName)"
        Write-Host "Action: $($_.ActionSuccess)"
        Write-Host "Time: $($_.InitialDetectionTime)`n"
    }
} else {
    Write-Host "`nNo recent threat detections" -ForegroundColor Green
}
