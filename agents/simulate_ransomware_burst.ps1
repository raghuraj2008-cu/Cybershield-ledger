Write-Host "💥 Starting Ransomware Encryption Burst Simulation..." -ForegroundColor Yellow

$TargetDir = "$env:TEMP\CyberShield_Ransomware_Watch"
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

# 1. Benign Write Simulation (Low Entropy ~3.0 - 3.5)
Write-Host "`n--- Phase 1: Writing Standard Plaintext Documents (Nominal) ---" -ForegroundColor Cyan
for ($i = 1; $i -le 3; $i++) {
    $plainText = "This is a regular business document containing plain english corporate records number $i. " * 50
    [System.IO.File]::WriteAllText("$TargetDir\normal_doc_$i.txt", $plainText)
    Write-Host "  Written: normal_doc_$i.txt (Plaintext)" -ForegroundColor Gray
    Start-Sleep -Milliseconds 200
}

Start-Sleep -Seconds 2

# 2. Malicious Encrypted Burst Simulation (High Entropy ~7.9+)
Write-Host "`n--- Phase 2: Simulating High-Entropy Ransomware Encryption Burst ---" -ForegroundColor Yellow
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

for ($i = 1; $i -le 3; $i++) {
    $cipherBytes = New-Object byte[] 4096
    $rng.GetBytes($cipherBytes)
    [System.IO.File]::WriteAllBytes("$TargetDir\locked_file_$i.locked", $cipherBytes)
    Write-Host "  Written: locked_file_$i.locked (High-Entropy Ciphertext)" -ForegroundColor Red
    Start-Sleep -Milliseconds 150
}

Write-Host "`n✅ Simulation Complete. Check Sentinel Terminal & SOC Dashboard." -ForegroundColor Green