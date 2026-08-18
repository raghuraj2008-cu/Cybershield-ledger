Write-Host "🚀 Launching CyberShield Ledger Full-Stack Platform..." -ForegroundColor Cyan

# 1. Start Hardhat Local EVM Blockchain Node
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\blockchain'; npx hardhat node"
Start-Sleep -Seconds 3

# 2. Start FastAPI REST Backend Engine
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; ..\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 3

# 3. Start SOAR Autonomous Containment Agent
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/soar_containment.ps1"
Start-Sleep -Seconds 1

# 4. Open SOC UI Visualizer Dashboard
Start-Process "$PSScriptRoot\frontend\index.html"

Write-Host "✅ All CyberShield microservices running." -ForegroundColor Green