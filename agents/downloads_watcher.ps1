$downloadsDir = [System.IO.Path]::Combine($env:USERPROFILE, "Downloads")
Write-Host "🛡️ CyberShield Real-Time Downloads Folder Watcher Active." -ForegroundColor Cyan
Write-Host "Monitoring: $downloadsDir" -ForegroundColor Yellow

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $downloadsDir
$watcher.Filter = "*.*"
$watcher.IncludeSubdirectories = $false
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $name = $Event.SourceEventArgs.Name
    Start-Sleep -Milliseconds 500
    
    if (Test-Path $path) {
        try {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue

            $isEicar = ($content -and $content -match "EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
            $isDangerousExt = $name -match "\.(exe|scr|vbs|bat|ps1|hta|iso|dll)$"

            $threatScore = 30
            $eventType = "FILE_DOWNLOAD_EVENT"
            $mitreTactic = "TA0001 - Initial Access (File Ingress)"

            if ($isEicar) {
                $threatScore = 99
                $eventType = "MALWARE_SIGNATURE_DETECTED"
                $mitreTactic = "TA0005 - Defense Evasion (Known Malicious Signature)"
            } elseif ($isDangerousExt) {
                $threatScore = 85
                $eventType = "SUSPICIOUS_EXECUTABLE_DOWNLOAD"
                $mitreTactic = "TA0002 - Execution (Untrusted Binary Ingress)"
            }

            $payload = @{
                event_id = [guid]::NewGuid().ToString()
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_type = $eventType
                user = $env:USERNAME
                source_host = "INTERNET-INGRESS"
                target_host = $env:COMPUTERNAME
                process_name = "browser_download.exe"
                command = "IngressFile: $name"
                threat_score = $threatScore
                mitre_tactic = $mitreTactic
                raw_message = "New file in Downloads: $name | SHA256: $hash"
            } | ConvertTo-Json

            $response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ingest" -Method Post -Body $payload -ContentType "application/json"
            
            if ($threatScore -ge 90) {
                Write-Host "`n🚨 [CRITICAL MALWARE INGESTION] $name | Score: $threatScore% | Leaf Anchored: $($response.leaf_hash.Substring(0, 16))..." -ForegroundColor Red
            } else {
                Write-Host "`n[INGRESS] $name | Score: $threatScore% | Leaf: $($response.leaf_hash.Substring(0, 16))..." -ForegroundColor Green
            }
        } catch {
            Write-Host "[-] Scan error on $($name): $_" -ForegroundColor DarkGray
        }
    }
}

Register-ObjectEvent $watcher 'Created' -Action $action | Out-Null

while ($true) {
    Start-Sleep -Seconds 1
}