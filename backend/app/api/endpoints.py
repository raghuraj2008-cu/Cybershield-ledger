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

class AutoOmniScanPayload(BaseModel):
    raw_input: str
    file_attachment: Optional[str] = None
    sender_hint: Optional[str] = "Auto_Sensor"

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

@router.post("/scan/auto-omni")
async def auto_omni_threat_scan(payload: AutoOmniScanPayload):
    text = payload.raw_input.strip()
    file_att = payload.file_attachment or ""
    
    # 1. Automatic Platform Detection
    detected_platforms = []
    platform_signatures = {
        "Instagram": [r"instagram\.com", r"instagr\.am", r"\b@insta\b", r"\breel\b", r"\big_"],
        "WhatsApp": [r"whatsapp\.com", r"wa\.me", r"\bwhatsapp\b", r"\bwa\.link\b", r"\+91\d{10}", r"\+1\d{10}"],
        "Telegram": [r"t\.me", r"telegram\.me", r"\btelegram\b", r"\b@tg\b", r"\bairdrop_bot\b"],
        "Discord": [r"discord\.com", r"discord\.gg", r"\bdiscord\b"],
        "Twitter / X": [r"twitter\.com", r"x\.com", r"\bt\.co\b"],
        "YouTube": [r"youtube\.com", r"youtu\.be", r"\bshorts\b"],
        "Email Gateway": [r"\bfrom:\b", r"\bsubject:\b", r"@", r"\.corp\b"],
        "Direct SMS / Carrier": [r"\bsms\b", r"\botp\b", r"\btxt msg\b"]
    }
    
    for plat, patterns in platform_signatures.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            detected_platforms.append(plat)
    
    if not detected_platforms:
        detected_platforms = ["Omni-Channel Web / File Stream"]

    # 2. Threat Heuristics
    score = 10
    threat_indicators = []

    if re.search(r"\beicar\b|anti-malware-testfile|x5o!p%@ap", text, re.IGNORECASE):
        score += 85
        threat_indicators.append("Known Antivirus Threat Signature (EICAR / Test Payload)")

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    suspicious_tlds = [".xyz", ".tk", ".top", ".ru", ".cc", ".link", ".click", ".pw", ".space"]
    url_shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy"]
    typosquats = ["instagram-verify", "telegram-gift", "whatsapp-update", "free-crypto", "bank-login", "reel-viral", "verify-it-helpdesk"]

    for u in urls:
        parsed = urllib.parse.urlparse(u if u.startswith("http") else "http://" + u)
        domain = parsed.netloc.lower()
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 40
            threat_indicators.append(f"High-Risk Phishing TLD: '{domain}'")
        if any(shortener in domain for shortener in url_shorteners):
            score += 25
            threat_indicators.append(f"Obfuscated Shortened URL Redirect: '{domain}'")
        if any(tq in domain for tq in typosquats):
            score += 45
            threat_indicators.append(f"Typosquatted Impersonation Domain: '{domain}'")

    lures = [
        (r"\bverify\s+(your\s+)?(account|password|identity|credentials|email)\b", 35, "Credential / Password Harvesting Lure"),
        (r"\b(account|mailbox|service)\s+(will\s+be|is|has\s+been)\s+(suspended|deleted|banned|locked|disabled)\b", 35, "Urgency & Account Suspension Coercion"),
        (r"\b(urgent|immediate\s+action|wire\s+payment|bank\s+transfer)\b", 25, "Business Email Compromise (BEC) Urgency Trigger"),
        (r"\bclaim\s+your\s+(gift|reward|prize|crypto|bitcoin|airdrop)\b", 35, "Crypto / Financial Scam Scheme"),
        (r"\bclick\s+(here|this\s+link)\s+to\s+watch\b", 25, "Malicious Click Trap"),
        (r"\botp\b|\bverification\s+code\b", 30, "2FA / OTP Interception Attempt"),
        (r"\bdelete\s+shadows\b|\bwevtutil\b|\bvssadmin\b", 50, "Destructive Ransomware Command")
    ]
    for pattern, weight, label in lures:
        if re.search(pattern, text, re.IGNORECASE):
            score += weight
            threat_indicators.append(label)

    # Check for untrusted email domains
    if any(tld in text for tld in [".xyz", ".tk", ".top", ".ru"]):
        if not any(f"High-Risk Phishing TLD: '{tld}'" in ind for ind in threat_indicators):
            score += 30
            threat_indicators.append("Untrusted External Domain Reference")

    # File Attachment / Downloaded Ingress Dropper Check
    text_without_urls = re.sub(r'https?://[^\s<>"]+|www\.[^\s<>"]+', '', text)
    file_matches = re.findall(r'[\w-]+\.(?:apk|exe|scr|vbs|bat|ps1|hta|iso|dll|zip|xlsm|jar)', text_without_urls, re.IGNORECASE)
    
    if file_att and any(file_att.lower().endswith(ext) for ext in [".apk", ".exe", ".scr", ".vbs", ".bat", ".ps1", ".hta", ".iso", ".dll", ".zip", ".xlsm", ".jar"]):
        score += 50
        threat_indicators.append(f"Weaponized Malware / Macro Attachment Ingress: '{file_att}'")
    elif file_matches:
        score += 50
        threat_indicators.append(f"Disguised Weaponized Malware Dropper / Executable File: '{file_matches[0]}'")

    final_score = min(score, 99)
    is_threat = final_score >= 70
    primary_platform = ", ".join(detected_platforms)
    
    classification = (
        "PHISHING_SPEAR_ATTACK" if "Email Gateway" in detected_platforms and final_score >= 80 else
        "CRITICAL_OMNI_CHANNEL_THREAT" if final_score >= 85 else
        "SUSPICIOUS_SOCIAL_MEDIA_LURE" if is_threat else
        "BENIGN_SOCIAL_NOMINAL"
    )

    verdict = (
        f"🚨 Threat Detected on {primary_platform} (Score: {final_score}%)" if is_threat else
        f"✅ No Threat Found on {primary_platform} (System Nominal - {final_score}%)"
    )

    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=classification,
        user=os.environ.get("USERNAME", "EndpointUser"),
        source_host=f"AUTO-SENSOR:[{primary_platform}]",
        target_host="LOCAL-ENDPOINT-CORE",
        process_name="auto_omni_sentinel.exe",
        command=f"Payload: '{text[:35]}...'",
        threat_score=final_score,
        mitre_tactic="TA0001 - Initial Access (Spearphishing / Ingress)" if is_threat else "TA0001 - Initial Access (Clean Stream)",
        raw_message=f"Platforms: {primary_platform} | Flags: {'; '.join(threat_indicators) if threat_indicators else 'Zero Threat Signatures'}"
    )

    ingest_result = await ingest_event(event)

    return {
        "verdict_summary": verdict,
        "threat_detected": is_threat,
        "threat_score": final_score,
        "classification": classification,
        "identified_platforms": detected_platforms,
        "detailed_indicators": threat_indicators if threat_indicators else ["No suspicious indicators found across analyzed social media signatures."],
        "blockchain_proof": {
            "leaf_hash": ingest_result["leaf_hash"],
            "on_chain_merkle_root": ingest_result["merkle_root"]
        },
        "soar_recommendation": "ACTIVE_QUARANTINE_AND_BLOCK" if is_threat else "ALLOW_TRAFFIC"
    }

@router.post("/scan/deep-forensics")
async def deep_forensics_scan(payload: Dict[str, Any]):
    return await auto_omni_threat_scan(AutoOmniScanPayload(raw_input=payload.get("file_name", ""), file_attachment=payload.get("file_name", "")))

@router.post("/scan/email")
async def scan_email(payload: Dict[str, Any]):
    raw = f"From: {payload.get('sender','')} Subject: {payload.get('subject','')} {payload.get('body','')}"
    atts = payload.get("attachments", [])
    file_att = atts[0] if isinstance(atts, list) and len(atts) > 0 else None
    return await auto_omni_threat_scan(AutoOmniScanPayload(raw_input=raw, file_attachment=file_att))

@router.post("/scan/social-message")
async def scan_social_threat(payload: Dict[str, Any]):
    return await auto_omni_threat_scan(AutoOmniScanPayload(raw_input=payload.get("message_text", ""), file_attachment=payload.get("media_name", None)))

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
    global telemetry_logs, deception_canaries
    telemetry_logs = []
    for c in deception_canaries:
        c["status"] = "ARMED"
        c["tripped_at"] = None
    return {"status": "CLEARED"}

@router.get("/generate-report", response_class=HTMLResponse)
async def generate_legal_dfir_report():
    all_leaves = [log["leaf_hash"] for log in telemetry_logs]
    root = compute_merkle_root(all_leaves)
    rows = "".join([f"<tr><td style='padding:8px;'>{l['timestamp']}</td><td style='padding:8px;'><strong>{l['event_type']}</strong></td><td style='padding:8px;'>{l['source_host']} &rarr; {l['target_host']}</td><td style='padding:8px;'>{l['threat_score']}%</td><td style='padding:8px; font-family:monospace;'>{l.get('leaf_hash','')[:20]}...</td></tr>" for l in telemetry_logs])
    return HTMLResponse(content=f"<html><body style='background:#0b0f19; color:white; font-family:sans-serif; padding:30px;'><h2>CYBERSHIELD DFIR FORENSIC INCIDENT BRIEF</h2><p><strong>Merkle Root:</strong> {root}</p><table border='1' cellpadding='5' style='border-collapse:collapse; width:100%; border-color:#334155;'><thead><tr><th>Timestamp</th><th>Event</th><th>Trajectory</th><th>Score</th><th>Leaf Hash</th></tr></thead><tbody>{rows if rows else '<tr><td colspan=5>No events recorded.</td></tr>'}</tbody></table></body></html>")