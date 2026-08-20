Add-Type -AssemblyName System.Windows.Forms

$watchFolder = "$env:USERPROFILE\Downloads"
$quarantineVault = "$env:TEMP\CyberShield_Quarantine"
if (-not (Test-Path $quarantineVault)) { New-Item -ItemType Directory -Path $quarantineVault | Out-Null }

Write-Host "🛡️ CyberShield Zero-Trust Ingress Sentinel & Deep Forensics Guard Active." -ForegroundColor Cyan
Write-Host "Watching ingress drop zone: $watchFolder" -ForegroundColor Yellow
Write-Host "Quarantine Vault: $quarantineVault" -ForegroundColor DarkGray

function Calculate-Entropy([string]$filePath) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        if ($bytes.Length -eq 0) { return 0.0 }
        $freq = @{}
        foreach ($b in $bytes) { $freq[$b] = ($freq[$b] + 1) }
        $entropy = 0.0
        foreach ($count in $freq.Values) {
            $p = $count / $bytes.Length
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($entropy, 3)
    } catch {
        return 0.0
    }
}

function Extract-Strings([string]$filePath) {
    try {
        $content = [System.IO.File]::ReadAllText($filePath)
        return @($content)
    } catch {
        return @()
    }
}

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $watchFolder
$watcher.Filter = "*.*"
$watcher.IncludeSubdirectories = $false
$watcher.EnableRaisingEvents = $true

$onCreated = {
    $filePath = $Event.SourceEventArgs.FullPath
    $fileName = $Event.SourceEventArgs.Name
    Start-Sleep -Milliseconds 400

    if (Test-Path $filePath) {
        Write-Host "`n⚡ [INGRESS DETECTED]: $fileName" -ForegroundColor Magenta

        # 1. Compute Cryptographic Hashes
        $sha256 = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
        $md5 = (Get-FileHash -Path $filePath -Algorithm MD5).Hash.ToLower()
        $fileSize = (Get-Item $filePath).Length
        $entropy = Calculate-Entropy $filePath
        $strings = Extract-Strings $filePath

        $signatures = @()
        if ($strings -match "EICAR-STANDARD-ANTIVIRUS-TEST-FILE") { $signatures += "EICAR_TEST_PAYLOAD" }

        # 2. Instant Pre-Execution Quarantine
        $quarantinedPath = Join-Path $quarantineVault "$fileName.quarantine"
        try {
            Move-Item -Path $filePath -Destination $quarantinedPath -Force
            $isQuarantined = $true
            Write-Host "🔒 PRE-EXECUTION QUARANTINE ENFORCED -> Moved to $quarantinedPath" -ForegroundColor Red
        } catch {
            $isQuarantined = $false
        }

        # 3. Dispatch Deep Forensics to Ingestion Core
        $payload = @{
            file_name = $fileName
            file_path = $filePath
            file_size_bytes = $fileSize
            sha256_hash = $sha256
            md5_hash = $md5
            entropy_score = $entropy
            extracted_strings = $strings
            detected_signatures = $signatures
            is_quarantined = $isQuarantined
        } | ConvertTo-Json

        try {
            $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scan/deep-forensics" -Method Post -Body $payload -ContentType "application/json"

            if ($res.threat_score -ge 80) {
                Write-Host "🚨 [CRITICAL DESTRUCTIVE PAYLOAD INTERCEPTED]" -ForegroundColor Red
                Write-Host "   Threat Score: $($res.threat_score)% | Status: $($res.classification)" -ForegroundColor Yellow
                Write-Host "   SHA-256:      $sha256" -ForegroundColor White
                Write-Host "   Entropy:      $entropy / 8.0" -ForegroundColor White
                Write-Host "   Forensic Flags:" -ForegroundColor DarkYellow
                foreach ($flag in $res.indicators) {
                    Write-Host "     • $flag" -ForegroundColor Red
                }
                Write-Host "   Blockchain Leaf: $($res.blockchain_leaf.Substring(0, 18))..." -ForegroundColor Cyan
                
                # Admin Toast Notification
                [System.Windows.Forms.MessageBox]::Show(
                    "🚨 CYBERSHIELD ALERT: Destructive payload '$fileName' was intercepted and quarantined before execution!`n`nThreat Score: $($res.threat_score)%`nSHA256: $($sha256.Substring(0,20))...`n`nDetails logged to Blockchain Evidence Ledger.",
                    "CyberShield Zero-Trust Alert",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            } else {
                Write-Host "✅ [BENIGN INGRESS VERIFIED]: $fileName | Score: $($res.threat_score)% (Nominal)" -ForegroundColor Green
            }
        } catch {
            Write-Host "[-] Deep Forensics API dispatch failed: $_" -ForegroundColor Red
        }
    }
}

Register-ObjectEvent $watcher "Created" -Action $onCreated | Out-Null

while ($true) { Start-Sleep -Seconds 1 }