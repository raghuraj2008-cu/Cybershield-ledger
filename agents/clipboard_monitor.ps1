Add-Type -AssemblyName System.Windows.Forms

Write-Host "🙰 CyberShield Real-Time Clipboard Sentinel Active..." -ForegroundColor Cyan
Write-Host "👍 Monitoring Clipboard Memory Stream. Press Ctrl+C to stop.`"" -ForegroundColor Green

$lastSeen = ""

while ($true) {
    Start-Sleep -Milliseconds 250
    $text = ""
    try {
        $text = [System.Windows.Forms.Clipboard]::GetText()
    } catch {
        continue
    }

    if ([string]::IsNullOrEmpty($text) -or $text -eq $lastSeen -or $text -eq "CYBERSHIELD_EDR_PURGED_MALICIOUS_PAYLOAD") {
        continue
    }
    $lastSeen = $text
    $isThreat = $false
    $reason = ""

    if ($text -match "powershell.*(-enc|-encodedcommand|-w\skhidden|DownloadString|IEX)" -or $text -match "cmd\.exe.*/c") {
        $isThreat = $true
        $reason = "Obfuscated Command Shellcode Execution"
    } elseif ($text -match "vssadmin.*delete\skshadows" -or $text -match "wevtutil.*cl") {
        $isThreat = $true
        $reason = "Destructive System Recovery Inhibition"
    }

    if ($isThreat) {
        Write-Host "`f[ALLERT] Malicious Payload Purged from Clipboard Memory!" -ForegroundColor Red
        Write-Host "  Reason: $reason" -ForegroundColor Yellow
        try {
            [System.Windows.Forms.Clipboard]::SetText("CYBERSHIELD_EDR_PURGED_MALICIOUS_PAYLOAD")
            $lastSeen = "CYBERSHIELD_EDR_PURGED_MALICIOUS_PAYLOAD"
            Write-Host "  Status: Clipboard sanitized to CYBERSHIELD_EDR_PURGED_MALICIOUS_PAYLOAD" -ForegroundColor Green
        } catch {}
    }
}