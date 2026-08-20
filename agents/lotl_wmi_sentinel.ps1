Write-Host "🛡️ CyberShield Living-off-the-Land (LotL) Process Sentinel Active..." -ForegroundColor Cyan
Write-Host "📍 Hooked to Windows WMI Process Creation Event Trace (Win32_ProcessStartTrace)" -ForegroundColor Yellow

$Query = "SELECT * FROM Win32_ProcessStartTrace"

$Action = {
    $procName = $Event.SourceEventArgs.NewEvent.ProcessName
    $procId   = $Event.SourceEventArgs.NewEvent.ProcessID
    $parentPid= $Event.SourceEventArgs.NewEvent.ParentProcessID

    # Query command line arguments safely
    $cmdLine = ""
    try {
        $procObj = Get-CimInstance Win32_Process -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
        if ($procObj) { $cmdLine = $procObj.CommandLine }
    } catch {}

    if ([string]::IsNullOrWhiteSpace($cmdLine)) { return }

    # Living-off-the-Land (LotL) Heuristic Detection Rules
    $threat = $null
    $score = 0
    $tactic = ""

    if ($cmdLine -match "vssadmin\s+delete\s+shadows" -or $cmdLine -match "wevtutil\s+cl") {
        $threat = "Anti-Recovery / Shadow Copy Deletion"
        $score = 98
        $tactic = "TA0040 - Impact (Inhibit System Recovery)"
    }
    elseif ($procName -match "certutil" -and ($cmdLine -match "-urlcache" -or $cmdLine -match "-split" -or $cmdLine -match "-f")) {
        $threat = "Dual-Use Binary Dropper Abuse (CertUtil Ingress)"
        $score = 95
        $tactic = "TA0011 - Command and Control (Ingress Tool Transfer)"
    }
    elseif ($procName -match "powershell" -and ($cmdLine -match "-enc" -or $cmdLine -match "-encodedcommand" -or $cmdLine -match "-w\s+hidden" -or $cmdLine -match "DownloadString")) {
        $threat = "Obfuscated / Stealth PowerShell Execution"
        $score = 92
        $tactic = "TA0002 - Execution (Command and Scripting Interpreter)"
    }
    elseif ($procName -match "procdump" -or ($procName -match "rundll32" -and $cmdLine -match "comsvcs.dll.*MiniDump")) {
        $threat = "LSASS Memory Credential Extraction"
        $score = 99
        $tactic = "TA0006 - Credential Access (OS Credential Dumping)"
    }

    if ($threat) {
        Write-Host "`n🚨 [CRITICAL ALERT] LotL Dual-Use Binary Exploitation Detected!" -ForegroundColor Red
        Write-Host "  Process: $procName (PID: $procId)" -ForegroundColor Yellow
        Write-Host "  Threat: $threat (Score: $score%)" -ForegroundColor Red
        Write-Host "  Payload: $cmdLine" -ForegroundColor Gray

        # Ingest Telemetry directly to CyberShield FastAPI Core
        $telemetry = @{
            event_id     = [Guid]::NewGuid().ToString()
            timestamp    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            event_type   = "LOTL_DUAL_USE_EXPLOIT"
            user         = $env:USERNAME
            source_host  = "HOST-PROCESS-SPAWNER"
            target_host  = "LOCAL-ENDPOINT-CORE"
            process_name = $procName
            command      = $cmdLine.Substring(0, [Math]::Min(120, $cmdLine.Length))
            threat_score = $score
            mitre_tactic = $tactic
            raw_message  = "LotL binary flagged: $threat | Command: $cmdLine"
        } | ConvertTo-Json

        try {
            $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ingest" -Method Post -Body $telemetry -ContentType "application/json"
            Write-Host "  Blockchain Merkle Leaf Anchored: $($res.merkle_root.Substring(0, 18))..." -ForegroundColor Cyan
        } catch {
            Write-Host "  FastAPI Ingestion Failed: $_" -ForegroundColor DarkGray
        }
    }
}

Register-WmiEvent -Query $Query -Action $Action | Out-Null
Write-Host "👀 Monitoring Windows process creation in real time. Press Ctrl+C to stop.`n" -ForegroundColor Green

while ($true) { Start-Sleep -Seconds 1 }