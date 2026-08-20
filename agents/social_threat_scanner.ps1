Write-Host "📱 CyberShield Omni-Channel & Social Media Threat Inspector Initiated..." -ForegroundColor Cyan

function Analyze-SocialMessage {
    param(
        [string]$Platform,
        [string]$Sender,
        [string]$Recipient,
        [string]$Message,
        [string]$MediaName = $null,
        [string[]]$Links = @()
    )

    $payload = @{
        platform = $Platform
        sender_id = $Sender
        recipient = $Recipient
        message_text = $Message
        media_name = $MediaName
        extracted_links = $Links
    } | ConvertTo-Json

    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scan/social-message" -Method Post -Body $payload -ContentType "application/json"

        if ($res.threat_score -ge 80) {
            Write-Host "`n🚨 [CRITICAL ATTACK INTERCEPTED - $Platform]" -ForegroundColor Red
            Write-Host "  Sender: $Sender -> Recipient: $Recipient" -ForegroundColor White
            Write-Host "  Message: $Message" -ForegroundColor Gray
            Write-Host "  Threat Score: $($res.threat_score)% | Classification: $($res.classification)" -ForegroundColor Yellow
            Write-Host "  Gathered Threat Intel Indicators:" -ForegroundColor DarkYellow
            foreach ($ind in $res.indicators) {
                Write-Host "    • $ind" -ForegroundColor Red
            }
            Write-Host "  SOAR Action: $($res.soar_recommendation)" -ForegroundColor Magenta
            Write-Host "  Immutable Blockchain Leaf: $($res.blockchain_proof.leaf_hash.Substring(0, 18))..." -ForegroundColor Cyan
        } else {
            Write-Host "`n✅ [CLEAN SOCIAL INTERACTION - $Platform]" -ForegroundColor Green
            Write-Host "  Sender: $Sender | Score: $($res.threat_score)% (Nominal / Clean)" -ForegroundColor White
        }
    } catch {
        Write-Host "[-] Inspection Error: $_" -ForegroundColor Red
    }
}

# --- Case 1: Normal WhatsApp Reel Share ---
Write-Host "`n--- Drill 1: Friend sharing a normal cooking reel on WhatsApp ---" -ForegroundColor Yellow
Analyze-SocialMessage -Platform "WhatsApp" -Sender "+919876543210" -Recipient "Raghuraj" -Message "Check out this funny reel bro!" -Links @("https://instagram.com/reel/C12345abcd")
Start-Sleep -Seconds 2

# --- Case 2: Instagram Phishing / Account Ban Threat ---
Write-Host "`n--- Drill 2: Fake Instagram Copyright / Ban Extortion DM ---" -ForegroundColor Yellow
Analyze-SocialMessage -Platform "Instagram" -Sender "@insta_official_security_team" -Recipient "@raghuraj_dev" -Message "URGENT: Your account will be banned in 24 hours due to copyright. Click here to verify your account: http://instagram-verify-badge.xyz/login" -Links @("http://instagram-verify-badge.xyz/login")
Start-Sleep -Seconds 2

# --- Case 3: Telegram Malicious Reel / Trojan Dropper ---
Write-Host "`n--- Drill 3: Telegram Video Dropper with Hidden Executable Payload ---" -ForegroundColor Yellow
Analyze-SocialMessage -Platform "Telegram" -Sender "@crypto_airdrop_bot" -Recipient "@raghuraj_tg" -Message "Claim your crypto reward! Download this exclusive video codec to watch the viral leak." -MediaName "viral_leak_video_codec.apk" -Links @("http://bit.ly/claim-free-bitcoin")