Write-Host "🚀 Launching CyberShield Ledger Full-Stack Platform..." -ForegroundColor Cyan

# 1. Hardhat Local EVM Blockchain Node
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\blockchain'; npx hardhat node"
Start-Sleep -Seconds 3

# 2. FastAPI REST Backend Engine
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; ..\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 3

# 3. SOAR Autonomous Containment Agent
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/soar_containment.ps1"

# 4. Downloads Folder Integrity Watcher
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/downloads_watcher.ps1"
Start-Sleep -Seconds 1

# 5. SOC UI Visualizer Dashboard
Start-Process "$PSScriptRoot\frontend\index.html"

Write-Host "✅ All CyberShield microservices and monitoring agents running." -ForegroundColor Green