$BackendUrl = "http://127.0.0.1:8000/api/v1/ingest"

# Ensure backend is online before starting
Write-Host "⏳ Checking FastAPI connection..." -ForegroundColor DarkGray
while ($true) {
    try {
        $check = Invoke-RestMethod -Uri "http://127.0.0.1:8000/" -Method Get -TimeoutSec 1
        if ($check.status -eq "CyberShield API Online") { break }
    } catch {
        Start-Sleep -Seconds 1
    }
}
Write-Host " Connected to CyberShield Backend." -ForegroundColor Green

$attackSteps = @(
    @{ user = "guest_user"; event = "AUTH_FAILURE"; process = "sshd.exe"; msg = "SSH Port 22 Brute-force attempt" },
    @{ user = "guest_user"; event = "AUTH_FAILURE"; process = "sshd.exe"; msg = "SSH Port 22 Password spray attempt" },
    @{ user = "admin_svc";  event = "AUTH_FAILURE"; process = "lsass.exe"; msg = "Admin credential unauthorized access" },
    @{ user = "admin_svc";  event = "PRIVILEGE_ESCALATION"; process = "powershell.exe"; msg = "SeDebugPrivilege token acquired" },
    @{ user = "SYSTEM";     event = "DATA_EXFILTRATION"; process = "curl.exe"; msg = "4.2GB payload outbound to 198.51.100.42" }
)

Write-Host "`n Initiating Simulated APT Cyberattack against CyberShield Ledger..." -ForegroundColor Red

foreach ($step in $attackSteps) {
    $payload = @{
        event_id     = [Guid]::NewGuid().ToString()
        timestamp    = (Get-Date).ToUniversalTime().ToString("o")
        source_host  = "PC-17"
        target_host  = "DC-PRIMARY"
        user         = $step.user
        event_type   = $step.event
        process_name = $step.process
        raw_message  = $step.msg
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $BackendUrl -Method Post -Body $payload -ContentType "application/json"
    $score = $response.threat_score
    $tactic = $response.mitre_tactic
    
    Write-Host "[$($step.event)] Threat Score: $score% -- MITRE Tactic: $tactic" -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

Write-Host "`n Querying On-Chain Merkle Root..." -ForegroundColor Cyan
$merkle = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/merkle-root"
Write-Host "Merkle Root: $($merkle.merkle_root)" -ForegroundColor Green
Write-Host "Total Events Anchored: $($merkle.total_events)" -ForegroundColor Green
