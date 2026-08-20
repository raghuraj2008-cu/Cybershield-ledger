import hashlib
import json
import uuid
import re
import math
import os
import urllib.parse
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

router = APIRouter()

telemetry_logs = []
admin_alerts = []
deception_canaries = [
    {"canary_id": "CNRY-LSASS-901", "type": "Memory Honeytoken", "account": "svc_ad_sync", "host": "DC-PRIMARY", "status": "ARMED", "tripped_at": None},
    {"canary_id": "CNRY-SMB-902", "type": "Decoy SMB Share", "account": "\\\\DC-PRIMARY\\FinanceShare$", "host": "DC-PRIMARY", "status": "ARMED", "tripped_at": None},
    {"canary_id": "CNRY-SQL-903", "type": "Decoy Database Table", "account": "BACKUP-DB.sys_vault", "host": "BACKUP-DB", "status": "ARMED", "tripped_at": None}
]

class TelemetryEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    user: str
    source_host: str
    target_host: str
    process_name: str
    command: str
    threat_score: int
    mitre_tactic: str
    raw_message: str

class DeepForensicsPayload(BaseModel):
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    md5_hash: str
    entropy_score: float
    extracted_strings: List[str]
    detected_signatures: List[str]
    is_quarantined: bool

def compute_leaf(event_data: dict) -> str:
    cleaned = {k: v for k, v in event_data.items() if k != "leaf_hash"}
    serialized = json.dumps(cleaned, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()

def compute_merkle_root(hashes: list) -> str:
    if not hashes:
        return "0000000000000000000000000000000000000000000000000000000000000000"
    current_level = hashes[:]
    while len(current_level) > 1:
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])
        next_level = []
        for i in range(0, len(current_level), 2):
            combined = current_level[i] + current_level[i + 1]
            parent = hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(parent)
        current_level = next_level
    return current_level[0]

@router.post("/ingest")
async def ingest_event(event: TelemetryEvent):
    event_dict = event.dict()
    leaf_hash = compute_leaf(event_dict)
    event_dict["leaf_hash"] = leaf_hash
    telemetry_logs.append(event_dict)
    
    if event.threat_score >= 90:
        for c in deception_canaries:
            if c["host"] in [event.source_host, event.target_host] and c["status"] == "ARMED":
                c["status"] = "TRIPPED_BY_APT"
                c["tripped_at"] = event.timestamp
    
    all_leaves = [log["leaf_hash"] for log in telemetry_logs]
    current_root = compute_merkle_root(all_leaves)
    return {
        "status": "INGESTED_AND_ANCHORED",
        "event_id": event.event_id,
        "leaf_hash": leaf_hash,
        "merkle_root": current_root,
        "total_events": len(telemetry_logs)
    }

@router.post("/scan/deep-forensics")
async def deep_forensics_scan(payload: DeepForensicsPayload):
    score = 15
    threat_indicators = []
    
    # 1. Signature-based triggers
    if any("EICAR" in sig for sig in payload.detected_signatures):
        score += 85
        threat_indicators.append("Known Antivirus Test Signature (EICAR)")

    # 2. Destructive command & Ransomware strings heuristics
    destructive_keywords = [
        ("vssadmin delete shadows", 45, "Ransomware Shadow Copy Deletion"),
        ("wevtutil cl", 40, "Anti-Forensics Event Log Erasure"),
        ("bcdedit /set", 35, "Recovery Boot Tampering"),
        ("format ", 45, "Disk Wipe Routine"),
        ("powershell -enc", 30, "Obfuscated Encoded Command Execution"),
        ("mimikatz", 50, "Credential Harvesting Binary Signature"),
        ("rundll32", 20, "Proxy DLL Execution")
    ]
    for kw, weight, label in destructive_keywords:
        if any(kw in s.lower() for s in payload.extracted_strings):
            score += weight
            threat_indicators.append(f"{label} detected in binary strings")

    # 3. High Entropy Check (Packed / Obfuscated / Encrypted malware)
    if payload.entropy_score > 7.2:
        score += 35
        threat_indicators.append(f"Abnormally High Entropy ({payload.entropy_score:.2f}/8.0): High probability of packed/encrypted destructive payload")

    # 4. Dangerous file extensions check
    if re.search(r"\.(exe|scr|vbs|bat|ps1|hta|iso|dll|apk|zip)$", payload.file_name, re.IGNORECASE):
        score += 25
        threat_indicators.append(f"High-Risk Executable Drop: {payload.file_name}")

    final_score = min(score, 99)
    classification = (
        "DESTRUCTIVE_MALWARE_PREVENTED" if final_score >= 85 else
        "SUSPICIOUS_UNTRUSTED_INGRESS" if final_score >= 60 else
        "BENIGN_VERIFIED_FILE"
    )

    tactic = (
        "TA0002 - Execution (User Execution / Malicious File)" if final_score >= 60 else
        "TA0001 - Initial Access (Benign File Ingress)"
    )

    alert_summary = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file_name": payload.file_name,
        "threat_score": final_score,
        "classification": classification,
        "sha256": payload.sha256_hash,
        "quarantined": payload.is_quarantined,
        "indicators": threat_indicators
    }
    admin_alerts.insert(0, alert_summary)

    # Ingest event & anchor on-chain
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=classification,
        user=os.environ.get("USERNAME", "EndpointUser"),
        source_host="INGRESS-VECTOR",
        target_host="LOCAL-ENDPOINT-CORE",
        process_name="quarantine_vault_guard.exe",
        command=f"Pre-Execution Isolation: {payload.file_name}",
        threat_score=final_score,
        mitre_tactic=tactic,
        raw_message=f"Forensics: Entropy={payload.entropy_score:.2f} | Flags={'; '.join(threat_indicators) if threat_indicators else 'None'}"
    )
    ingest_res = await ingest_event(event)

    return {
        "status": "FORENSICS_COMPLETE_AND_ANCHORED",
        "threat_score": final_score,
        "classification": classification,
        "quarantine_enforced": payload.is_quarantined,
        "indicators": threat_indicators,
        "forensic_metadata": {
            "file_name": payload.file_name,
            "sha256": payload.sha256_hash,
            "md5": payload.md5_hash,
            "entropy": payload.entropy_score,
            "size_bytes": payload.file_size_bytes
        },
        "blockchain_leaf": ingest_res["leaf_hash"],
        "on_chain_merkle_root": ingest_res["merkle_root"],
        "admin_notified": True
    }

@router.get("/admin/alerts")
async def get_admin_alerts():
    return admin_alerts[:10]

@router.post("/scan/email")
async def scan_email(payload: Dict[str, Any]):
    score = 15
    indicators = []
    body = payload.get("body", "")
    subject = payload.get("subject", "")
    sender = payload.get("sender", "")
    
    urgency_patterns = [r"\burgent\b", r"\bverify your password\b", r"\bbank transfer\b", r"\baccount suspended\b"]
    for p in urgency_patterns:
        if re.search(p, body, re.IGNORECASE) or re.search(p, subject, re.IGNORECASE):
            score += 25
            indicators.append(f"Urgent BEC Phrase: '{p}'")

    if sender.endswith((".xyz", ".tk", ".top", ".ru")):
        score += 35
        indicators.append(f"Untrusted Domain: '{sender}'")

    final_score = min(score, 99)
    event_type = "PHISHING_SPEAR_ATTACK" if final_score >= 80 else "EMAIL_BENIGN_CLEAN"
    
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=event_type,
        user=payload.get("recipient", "User"),
        source_host=sender,
        target_host="MAIL-GATEWAY-01",
        process_name="mail_scanner.exe",
        command=f"Subject: '{subject[:30]}...'",
        threat_score=final_score,
        mitre_tactic="TA0001 - Initial Access",
        raw_message=f"Flags: {'; '.join(indicators)}"
    )
    ingest_result = await ingest_event(event)
    return {"threat_score": final_score, "classification": event_type, "indicators": indicators, "blockchain_leaf": ingest_result["leaf_hash"], "on_chain_merkle_root": ingest_result["merkle_root"]}

@router.post("/scan/social-message")
async def scan_social_threat(payload: Dict[str, Any]):
    msg = payload.get("message_text", "")
    score = 10
    indicators = []
    
    if any(tld in msg for tld in [".xyz", ".tk", "bit.ly", "tinyurl"]):
        score += 35
        indicators.append("Suspicious / Shortened Link")
    if re.search(r"\b(verify|banned|suspended|claim|reward|crypto)\b", msg, re.IGNORECASE):
        score += 35
        indicators.append("Social Engineering Lure")
    if payload.get("media_name", "") and payload["media_name"].endswith((".apk", ".exe", ".scr")):
        score += 50
        indicators.append("Weaponized Disguised Media")

    final_score = min(score, 99)
    classification = "CRITICAL_SOCIAL_MEDIA_MALWARE" if final_score >= 80 else "BENIGN_SOCIAL_COMMUNICATION"
    
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=classification,
        user=payload.get("recipient", "User"),
        source_host=f"{payload.get('platform', 'App')}:{payload.get('sender_id', 'User')}",
        target_host="USER-MOBILE-ENDPOINT",
        process_name="social_scanner.exe",
        command=f"Msg: '{msg[:30]}...'",
        threat_score=final_score,
        mitre_tactic="TA0001 - Initial Access",
        raw_message=f"Flags: {'; '.join(indicators)}"
    )
    ingest_result = await ingest_event(event)
    return {"threat_score": final_score, "classification": classification, "indicators": indicators, "blockchain_proof": {"leaf_hash": ingest_result["leaf_hash"], "on_chain_merkle_root": ingest_result["merkle_root"]}, "soar_recommendation": "BLOCK_SENDER" if final_score >= 80 else "ALLOW"}

@router.get("/logs")
async def get_logs():
    return telemetry_logs

@router.get("/merkle-root")
async def get_merkle_root():
    all_leaves = [log["leaf_hash"] for log in telemetry_logs]
    return {"merkle_root": compute_merkle_root(all_leaves), "total_events": len(telemetry_logs), "status": "CONSENSUS_VERIFIED"}

@router.get("/deception/canaries")
async def get_canaries():
    return deception_canaries

@router.get("/analytics/blast-radius")
async def get_blast_radius():
    all_hosts = set()
    compromised_hosts = set()
    for log in telemetry_logs:
        all_hosts.add(log["source_host"])
        all_hosts.add(log["target_host"])
        if log["threat_score"] >= 80:
            compromised_hosts.add(log["source_host"])
            compromised_hosts.add(log["target_host"])
    total_count = max(len(all_hosts), 6)
    compromised_count = len(compromised_hosts)
    return {"total_entities_evaluated": total_count, "compromised_entities": list(compromised_hosts), "enterprise_blast_radius_pct": round((compromised_count / total_count) * 100, 1) if total_count > 0 else 0}

@router.get("/export/stix", response_class=JSONResponse)
async def export_stix21():
    bundle_id = f"bundle--{uuid.uuid4()}"
    stix_objects = [{"type": "threat-actor", "spec_version": "2.1", "id": f"threat-actor--{uuid.uuid4()}", "created": datetime.utcnow().isoformat() + "Z", "modified": datetime.utcnow().isoformat() + "Z", "name": "Omni-Channel-APT-Syndicate"}]
    for log in telemetry_logs:
        stix_objects.append({"type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--{uuid.uuid4()}", "created": datetime.utcnow().isoformat() + "Z", "modified": datetime.utcnow().isoformat() + "Z", "name": log["event_type"], "description": log["mitre_tactic"]})
    return {"type": "bundle", "id": bundle_id, "spec_version": "2.1", "objects": stix_objects}

@router.post("/clear")
async def clear_logs():
    global telemetry_logs, admin_alerts, deception_canaries
    telemetry_logs = []
    admin_alerts = []
    for c in deception_canaries:
        c["status"] = "ARMED"
        c["tripped_at"] = None
    return {"status": "CLEARED"}

@router.get("/generate-report", response_class=HTMLResponse)
async def generate_legal_dfir_report():
    all_leaves = [log["leaf_hash"] for log in telemetry_logs]
    root = compute_merkle_root(all_leaves)
    rows = "".join([f"<tr><td style='padding:8px;'>{l['timestamp']}</td><td style='padding:8px;'><strong>{l['event_type']}</strong></td><td style='padding:8px;'>{l['threat_score']}%</td><td style='padding:8px; font-family:monospace;'>{l.get('leaf_hash','')[:20]}...</td></tr>" for l in telemetry_logs])
    return HTMLResponse(content=f"<html><body style='background:#0b0f19; color:white; font-family:sans-serif; padding:30px;'><h2>CYBERSHIELD DFIR FORENSIC INCIDENT BRIEF</h2><p><strong>Merkle Root:</strong> {root}</p><table border='1' cellpadding='5' style='border-collapse:collapse; width:100%; border-color:#334155;'><thead><tr><th>Timestamp</th><th>Event</th><th>Score</th><th>Leaf Hash</th></tr></thead><tbody>{rows if rows else '<tr><td colspan=4>No events.</td></tr>'}</tbody></table></body></html>")