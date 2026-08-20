Write-Host "📧 CyberShield Phishing & Email Security Agent Initiated..." -ForegroundColor Cyan

function Send-EmailScan {
    param(
        [string]$Sender,
        [string]$Recipient,
        [string]$Subject,
        [string]$Body,
        [string[]]$Attachments
    )

    $payload = @{
        sender = $Sender
        recipient = $Recipient
        subject = $Subject
        body = $Body
        attachments = $Attachments
    } | ConvertTo-Json

    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scan/email" -Method Post -Body $payload -ContentType "application/json"
        if ($res.threat_score -ge 80) {
            Write-Host "`n🚨 [CRITICAL PHISHING ATTACK DETECTED]" -ForegroundColor Red
            Write-Host "  From: $Sender -> To: $Recipient" -ForegroundColor White
            Write-Host "  Subject: $Subject" -ForegroundColor Gray
            Write-Host "  Score: $($res.threat_score)% | Type: $($res.classification)" -ForegroundColor Yellow
            Write-Host "  Indicators: $($res.indicators -join ', ')" -ForegroundColor DarkYellow
            Write-Host "  Blockchain Leaf: $($res.blockchain_leaf.Substring(0, 18))..." -ForegroundColor Cyan
        } else {
            Write-Host "`n✅ [CLEAN EMAIL INGESTION]" -ForegroundColor Green
            Write-Host "  From: $Sender -> Subject: $Subject | Score: $($res.threat_score)% (Nominal)" -ForegroundColor White
        }
    } catch {
        Write-Host "[-] Scan error: $_" -ForegroundColor Red
    }
}

Write-Host "`n--- Drill 1: Ingesting Normal Business Email ---" -ForegroundColor Yellow
Send-EmailScan -Sender "hr@university.edu" -Recipient "$env:USERNAME@internal.corp" -Subject "Quarterly Academic Calendar Update" -Body "Please review the updated semester schedule on the portal." -Attachments @("academic_calendar.pdf")
Start-Sleep -Seconds 2

Write-Host "`n--- Drill 2: Ingesting Weaponized Spearphishing Attack ---" -ForegroundColor Yellow
Send-EmailScan -Sender "admin-alert@verify-it-helpdesk.xyz" -Recipient "cfo@internal.corp" -Subject "URGENT: Immediate Action Required - Account Suspended" -Body "Your account has been suspended. Please verify your password immediately to avoid wire payment disruption." -Attachments @("invoice_macro_payload.xlsm")