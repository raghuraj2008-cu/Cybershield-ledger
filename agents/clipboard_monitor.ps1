Add-Type -AssemblyName System.Windows.Forms

Write-Host "📋 CyberShield Real-Time Clipboard Sentinel Active." -ForegroundColor Cyan
Write-Host "Listening for copied text, social media links, reels, and message payloads..." -ForegroundColor Yellow

$lastText = ""

while ($true) {
    try {
        if ([System.Windows.Forms.Clipboard]::ContainsText()) {
            $currentText = [System.Windows.Forms.Clipboard]::GetText().Trim()
            
            if ($currentText -and $currentText -ne $lastText) {
                $lastText = $currentText
                
                # Check if text contains URL or actionable message strings
                if ($currentText.Length -gt 5) {
                    $platform = "Unknown_App"
                    if ($currentText -match "(instagram\.com|instagr\.am)") { $platform = "Instagram" }
                    elseif ($currentText -match "(t\.me|telegram)") { $platform = "Telegram" }
                    elseif ($currentText -match "(wa\.me|whatsapp)") { $platform = "WhatsApp" }
                    elseif ($currentText -match "(discord\.com|discord\.gg)") { $platform = "Discord" }
                    elseif ($currentText -match "https?://") { $platform = "Web_Browser" }
                    else { $platform = "Clipboard_Text" }

                    $payload = @{
                        platform = $platform
                        sender_id = "Clipboard_Interceptor"
                        recipient = $env:USERNAME
                        message_text = $currentText
                        media_name = $null
                        extracted_links = @()
                    } | ConvertTo-Json

                    $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scan/social-message" -Method Post -Body $payload -ContentType "application/json"

                    if ($res.threat_score -ge 80) {
                        Write-Host "`n🚨 [CLIPBOARD THREAT INTERCEPTED]" -ForegroundColor Red
                        Write-Host "  Platform Source: $platform" -ForegroundColor White
                        Write-Host "  Copied String:   $($currentText.Substring(0, [Math]::Min(50, $currentText.Length)))..." -ForegroundColor Gray
                        Write-Host "  Threat Rating:   $($res.threat_score)% ($($res.classification))" -ForegroundColor Yellow
                        Write-Host "  SOAR Action:     $($res.soar_recommendation)" -ForegroundColor Magenta
                        Write-Host "  Blockchain Leaf: $($res.blockchain_proof.leaf_hash.Substring(0, 18))..." -ForegroundColor Cyan
                        
                        # Neutralize clipboard to protect the user from accidental execution/pasting
                        [System.Windows.Forms.Clipboard]::SetText("[MALICIOUS_LINK_PURGED_BY_CYBERSHIELD_EDR]")
                        Write-Host "  🛡️ Clipboard sanitized with safety banner." -ForegroundColor DarkGreen
                    } else {
                        Write-Host "`n📋 [CLIPBOARD NOMINAL] ($platform) Score: $($res.threat_score)%" -ForegroundColor Green
                    }
                }
            }
        }
    } catch {
        # Ignore COM clipboard lock contention
    }
    Start-Sleep -Milliseconds 600
}