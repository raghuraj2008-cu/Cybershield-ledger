$BackendUrl = "http://127.0.0.1:8000/api/v1/ingest"
$MachineName = $env:COMPUTERNAME
Write-Host "🛡️ CyberShield Live Windows Agent Active. Monitoring Security Logs..." -ForegroundColor Cyan

# Continuous log polling for Logon (4624) and Failed Logon (4625)
$Query = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 5000]]]"

while ($true) {
    try {
        $Events = Get-WinEvent -LogName "Security" -FilterXPath $Query -ErrorAction SilentlyContinue
        foreach ($evt in $Events) {
            $eventType = if ($evt.Id -eq 4624) { "AUTH_SUCCESS" } else { "AUTH_FAILURE" }
            $userName = if ($evt.Properties.Count -gt 5) { $evt.Properties[5].Value } else { "SYSTEM" }
            
            $payload = @{
                event_id     = [Guid]::NewGuid().ToString()
                timestamp    = $evt.TimeCreated.ToUniversalTime().ToString("o")
                source_host  = $MachineName
                target_host  = "DC-PRIMARY"
                user         = [string]$userName
                event_type   = $eventType
                process_name = "lsass.exe"
                raw_message  = "Windows Event ID $($evt.Id) logged for user $userName"
            } | ConvertTo-Json

            $res = Invoke-RestMethod -Uri $BackendUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 2
            Write-Host "[+] Live WinEvent ($eventType) -> Threat Score: $($res.threat_score)% | Root Updated" -ForegroundColor Green
        }
    } catch {
        # Backend reconnecting or no new events
    }
    Start-Sleep -Seconds 2
}
