Write-Host "🛑 Shutting down CyberShield Ledger microservices..." -ForegroundColor Yellow
Stop-Process -Name "uvicorn", "node" -ErrorAction SilentlyContinue
Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match "npx hardhat node|uvicorn|soar_containment" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "✅ All processes cleanly terminated." -ForegroundColor Green