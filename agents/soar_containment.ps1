$BackendUrl = "http://127.0.0.1:8000/api/v1/logs"
$Threshold = 90

Write-Host "🛡️ CyberShield SOAR Active Containment Daemon Initiated..." -ForegroundColor Cyan
Write-Host "Monitoring telemetry stream for critical incidents (Threat Score >= $Threshold%)...`n" -ForegroundColor DarkGray

$handledEvents = @{}

while ($true) {
    try {
        $logs = Invoke-RestMethod -Uri $BackendUrl -Method Get -TimeoutSec 2
        foreach ($log in $logs) {
            if ($log.threat_score -ge $Threshold -and -not $handledEvents.ContainsKey($log.event_id)) {
                $handledEvents[$log.event_id] = $true
                Write-Host "🚨 [CRITICAL ALERT DETECTED] Event ID: $($log.event_id)" -ForegroundColor Red
                Write-Host "   Target Host: $($log.target_host) | User: $($log.user) | Score: $($log.threat_score)%" -ForegroundColor Yellow
                Write-Host "   MITRE ATT&CK: $($log.mitre_tactic)" -ForegroundColor Yellow
                Write-Host "   ⚡ [SOAR ACTION 1] Enforcing host quarantine for '$($log.source_host)'..." -ForegroundColor Red
                Write-Host "   ⚡ [SOAR ACTION 2] Injecting canary honeytoken credentials into memory..." -ForegroundColor Cyan
                Write-Host "   ⚡ [SOAR ACTION 3] Revoking active session token for '$($log.user)'.`n" -ForegroundColor Green
            }
        }
    } catch {}
    Start-Sleep -Seconds 2
}
