Write-Host "🚀 Launching CyberShield Ledger Enterprise 2.0 Full Stack..." -ForegroundColor Cyan

# 1. Local EVM Blockchain Node
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\blockchain'; npx hardhat node"
Start-Sleep -Seconds 3

# 2. FastAPI REST Backend Core
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; ..\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 3

# 3. Autonomous SOAR Agent
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/soar_containment.ps1"

# 4. Downloads Folder Integrity Watcher
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/downloads_watcher.ps1"

# 5. Real-Time Clipboard Sentinel
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; powershell -ExecutionPolicy Bypass -File agents/clipboard_monitor.ps1"
Start-Sleep -Seconds 1

# 6. Open Web SOC Visualizer
Start-Process "$PSScriptRoot\frontend\index.html"

Write-Host "✅ All CyberShield microservices, blockchain nodes, and defensive agents are live." -ForegroundColor Green