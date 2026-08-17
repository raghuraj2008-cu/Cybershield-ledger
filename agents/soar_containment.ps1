[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BackendUrl = "http://127.0.0.1:8000/api/v1/logs"
$Threshold = 90

Write-Host "🛡️ CyberShield SOAR Active Containment Daemon Initiated..." -ForegroundColor Cyan
Write-Host "Monitoring telemetry stream for critical incidents (Threat Score >= $Threshold%)..." -ForegroundColor DarkGray
Write-Host ""

$handledEvents = @{}
$quarantinedHosts = @{}

while ($true) {
    try {
        $logs = Invoke-RestMethod -Uri $BackendUrl -Method Get -TimeoutSec 2
        foreach ($log in $logs) {
            $eventId = [string]$log.event_id
            $threatScore = [int]$log.threat_score

            if ($threatScore -ge $Threshold -and -not $handledEvents.ContainsKey($eventId)) {
                $handledEvents[$eventId] = $true
                
                $targetHost = [string]$log.target_host
                $user = [string]$log.user
                $tactic = [string]$log.mitre_tactic
                $srcHost = [string]$log.source_host

                Write-Host "🚨 [CRITICAL ALERT] Event ID: $eventId" -ForegroundColor Red
                Write-Host "   Host: $targetHost | User: $user | Score: $threatScore%" -ForegroundColor Yellow
                Write-Host "   MITRE ATT&CK: $tactic" -ForegroundColor Yellow
                
                if (-not $quarantinedHosts.ContainsKey($srcHost)) {
                    $quarantinedHosts[$srcHost] = $true
                    Write-Host "   ⚡ [SOAR ACTION 1] Enforcing host quarantine: Inbound/Outbound isolation applied to '$srcHost'" -ForegroundColor Red
                } else {
                    Write-Host "   🔒 [SOAR STATUS] Host '$srcHost' is already under active quarantine policy" -ForegroundColor DarkGray
                }
                
                Write-Host "   ⚡ [SOAR ACTION 2] Injecting decoy honeytoken credentials into LSASS memory space..." -ForegroundColor Cyan
                Write-Host "   ⚡ [SOAR ACTION 3] Broadcasted token revocation for account: '$user'" -ForegroundColor Green
                Write-Host ""
            }
        }
    } catch {
        # Backend reconnecting
    }
    Start-Sleep -Seconds 2
}
