Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "🛡️  CYBERSHIELD LEDGER ENTERPRISE 2.0 — LIVE DEFENSE DRILL" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Start Backend Server
Write-Host "`n[1/5] Starting FastAPI Defense Backend on Port 8000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; .\venv\Scripts\Activate.ps1; cd backend; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 3

# 2. Open SOC Dashboard
Write-Host "[2/5] Launching Interactive Defense SOC Dashboard..." -ForegroundColor Yellow
Start-Process "file:///$PWD/frontend/index.html?token=$((Get-Date).Ticks)"
Start-Sleep -Seconds 2

# 3. Launch Entropy Watcher & LotL Sentinels
Write-Host "[3/5] Spawning Behavioral Host Sentinels..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; powershell -ExecutionPolicy Bypass -File agents/ransomware_entropy_sentinel.ps1"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; powershell -ExecutionPolicy Bypass -File agents/lotl_wmi_sentinel.ps1"
Start-Sleep -Seconds 2

# 4. Trigger Ransomware & LotL Ingress Vectors
Write-Host "[4/5] Executing Simulated Attack Vectors..." -ForegroundColor Red
powershell -ExecutionPolicy Bypass -File agents/simulate_ransomware_burst.ps1
powershell -ExecutionPolicy Bypass -File agents/simulate_lotl_attack.ps1

# 5. Run Verification CLI
Write-Host "`n[5/5] Performing Cryptographic Merkle Root Verification..." -ForegroundColor Green
.\venv\Scripts\python.exe backend/app/verify_proof.py

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "✅ LIVE DEMO PIPELINE FULLY ACTIVE & TELEMETRY STREAMING" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan