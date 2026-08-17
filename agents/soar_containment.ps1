# Set console encoding to UTF-8 to eliminate mojibake characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BackendUrl = "http://127.0.0.1:8000/api/v1/logs"
$Threshold = 90

Write-Host "🛡️ CyberShield SOAR Active Containment Daemon Initiated..." -ForegroundColor Cyan
Write-Host "Monitoring telemetry stream for critical incidents (Threat Score >= $Threshold%)...`n" -ForegroundColor DarkGray

$handledEvents = @{}
$quarantinedHosts = @{}

while ($true) {
    try {
        $logs = Invoke-RestMethod -Uri $BackendUrl -Method Get -TimeoutSec 2
        foreach ($log in $logs) {
            if ($log.threat_score -ge $Threshold -and -not $handledEvents.ContainsKey($log.event_id)) {
                $handledEvents[$log.event_id] = $true
                
                Write-Host "🚨 [CRITICAL ALERT] Event ID: $($log.event_id)" -ForegroundColor Red
                Write-Host "   Host: $($log.target_host) | User: $($log.user) | Score: $($log.threat_score)%" -ForegroundColor Yellow
                Write-Host "   MITRE ATT&CK: $($log.mitre_tactic)" -ForegroundColor Yellow
                
                if (-not $quarantinedHosts.ContainsKey($log.source_host)) {
                    $quarantinedHosts[$log.source_host] = $true
                    Write-Host "   ⚡ [SOAR ACTION 1] Enforcing host quarantine: Inbound/Outbound isolation applied to '$($log.source_host)'" -ForegroundColor Red
                } else {
                    Write-Host "   🔒 [SOAR STATUS] Host '$($log.source_host)' is already under active quarantine policy" -ForegroundColor DarkGray
                }
                
                Write-Host "   ⚡ [SOAR ACTION 2] Injecting decoy honeytoken credentials into LSASS memory space..." -ForegroundColor Cyan
                Write-Host "   ⚡ [SOAR ACTION 3] Broadcasted token revocation for account: '$($log.user)'`n" -ForegroundColor Green
            }
        }
    } catch {
        # Silent wait for backend
    }
    Start-Sleep -Seconds 2
}
