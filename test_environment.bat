@echo off
echo === Environment Test - Windows Target System ===
echo.

echo [*] Checking Windows Defender status...
powershell -Command "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled" 2>nul
if %errorlevel% == 0 (
    echo     [+] Windows Defender accessible
) else (
    echo     [-] Cannot check Defender status
)

echo.
echo [*] Checking Python installation...
python --version 2>nul
if %errorlevel% == 0 (
    echo     [+] Python installed
) else (
    echo     [-] Python not found
)

echo.
echo [*] Checking PowerShell scripts...
if exist "C:\Users\Public\Desktop\test_defender_status.ps1" (
    echo     [+] test_defender_status.ps1 found
) else (
    echo     [-] test_defender_status.ps1 missing
)

if exist "C:\Users\Public\Desktop\verify_evasion.ps1" (
    echo     [+] verify_evasion.ps1 found
) else (
    echo     [-] verify_evasion.ps1 missing
)

if exist "C:\Users\Public\Desktop\check_defender_logs.ps1" (
    echo     [+] check_defender_logs.ps1 found
) else (
    echo     [-] check_defender_logs.ps1 missing
)

echo.
echo [*] Checking Payloads directory...
if exist "C:\Users\Public\Desktop\Payloads" (
    echo     [+] Payloads directory exists
) else (
    echo     [-] Payloads directory missing
)

echo.
echo [*] System Information:
echo     Computer Name: %COMPUTERNAME%
echo     Username: %USERNAME%

echo.
echo [+] Environment test complete
echo [*] Ready to test Windows Defender evasion!
echo.
pause
