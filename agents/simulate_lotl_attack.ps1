Write-Host "💥 Starting Living-off-the-Land (LotL) Dual-Use Attack Simulation..." -ForegroundColor Yellow

# Phase 1: Benign Command Execution
Write-Host "`n--- Phase 1: Benign System Utility Execution ---" -ForegroundColor Cyan
& cmd.exe /c "echo System baseline nominal"
Start-Sleep -Seconds 2

# Phase 2: Obfuscated Encoded PowerShell Execution (TA0002)
Write-Host "`n--- Phase 2: Simulating Stealth Obfuscated PowerShell Shellcode Ingress ---" -ForegroundColor Yellow
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Output 'Simulated Shellcode Stage'"))
Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $encodedCommand"
Start-Sleep -Seconds 2

# Phase 3: Simulated Shadow Copy Invalidation Command Pattern (TA0040)
Write-Host "`n--- Phase 3: Simulating Inhibit Recovery Command Pattern ---" -ForegroundColor Red
Start-Process cmd.exe -ArgumentList "/c echo Testing: vssadmin delete shadows /all /quiet" -WindowStyle Hidden
Start-Sleep -Seconds 2

Write-Host "`n✅ LotL Simulation Finished. Check Sentinel Terminal & SOC Dashboard." -ForegroundColor Green