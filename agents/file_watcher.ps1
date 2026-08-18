$inboxDir = "$PSScriptRoot\..\test_inbox"
if (-not (Test-Path $inboxDir)) {
    New-Item -ItemType Directory -Path $inboxDir | Out-Null
}

$resolvedInbox = (Resolve-Path $inboxDir).Path
Write-Host "🛡️ CyberShield Real-Time File Integrity Agent Active." -ForegroundColor Cyan
Write-Host "Watching Directory: $resolvedInbox" -ForegroundColor Yellow

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $resolvedInbox
$watcher.Filter = "*.*"
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $name = $Event.SourceEventArgs.Name
    Start-Sleep -Milliseconds 300
    
    if (Test-Path $path) {
        $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue

        $isEicar = $content -match "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $threatScore = if ($isEicar) { 98 } else { 40 }
        $eventType = if ($isEicar) { "EICAR_DETECTION_TRIGGER" } else { "FILE_CREATION_EVENT" }
        $mitreTactic = if ($isEicar) { "TA0005 - Defense Evasion (Indicator Match)" } else { "TA0007 - Discovery (File System)" }

        $payload = @{
            event_id = [guid]::NewGuid().ToString()
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            event_type = $eventType
            user = $env:USERNAME
            source_host = $env:COMPUTERNAME
            target_host = "DC-PRIMARY"
            process_name = "explorer.exe"
            command = "MaliciousFileDrop: $name"
            threat_score = $threatScore
            mitre_tactic = $mitreTactic
            raw_message = "File dropped in inbox. SHA256: $hash"
        } | ConvertTo-Json

        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ingest" -Method Post -Body $payload -ContentType "application/json"
            Write-Host "`n🚨 [MALWARE DETECTION] File: $name | Score: $threatScore% | Leaf: $($response.leaf_hash.Substring(0, 16))..." -ForegroundColor Red
        } catch {
            Write-Host "`n[-] Ingestion error: $_" -ForegroundColor DarkRed
        }
    }
}

Register-ObjectEvent $watcher 'Created' -Action $action | Out-Null

while ($true) {
    Start-Sleep -Seconds 1
}