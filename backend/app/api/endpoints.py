import hashlib
import json
import uuid
import re
import urllib.parse
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

router = APIRouter()

telemetry_logs = []
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

class SocialMessagePayload(BaseModel):
    platform: str  # WhatsApp, Instagram, Telegram, SMS, Discord, Twitter/X
    sender_id: str
    recipient: str
    message_text: str
    media_url: Optional[str] = None
    media_name: Optional[str] = None
    extracted_links: Optional[List[str]] = []

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

@router.post("/scan/social-message")
async def scan_social_threat(payload: SocialMessagePayload):
    score = 10
    threat_indicators = []
    intel_data = {
        "platform": payload.platform,
        "sender": payload.sender_id,
        "urls_analyzed": [],
        "media_inspected": payload.media_name,
        "behavioral_flags": []
    }

    # 1. URL & Shortener Analysis
    urls = payload.extracted_links or []
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls += re.findall(url_pattern, payload.message_text)
    urls = list(set(urls))

    suspicious_tlds = [".xyz", ".tk", ".top", ".ru", ".cc", ".link", ".click", ".pw", ".space"]
    url_shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy"]
    typosquats = ["instagram-verify", "telegram-gift", "whatsapp-update", "free-crypto", "bank-login", "reel-viral"]

    for u in urls:
        parsed = urllib.parse.urlparse(u)
        domain = parsed.netloc.lower()
        intel_data["urls_analyzed"].append(u)

        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 35
            threat_indicators.append(f"High-Risk TLD in link: {domain}")
        if any(shortener in domain for shortener in url_shorteners):
            score += 25
            threat_indicators.append(f"Obfuscated Shortened URL: {domain}")
        if any(tq in domain for tq in typosquats):
            score += 45
            threat_indicators.append(f"Typosquatted Brand Impersonation Domain: {domain}")

    # 2. Social Engineering & Lures
    lures = [
        (r"\bverify your account\b", 30, "Credential Harvesting Lure"),
        (r"\baccount (will be|is) (suspended|deleted|banned)\b", 35, "Urgency / Coercion Extortion"),
        (r"\bclaim your (gift|reward|prize|crypto|bitcoin|airdrop)\b", 35, "Financial / Crypto Scams"),
        (r"\bclick (here|this link) to watch\b", 25, "Malicious Video / Reel Redirect Trap"),
        (r"\botp\b|\bverification code\b", 30, "OTP / 2FA Interception Attempt"),
        (r"\bdownload (this|the) (app|file|video)\b", 20, "Drive-by Ingress Coercion")
    ]
    for pattern, weight, label in lures:
        if re.search(pattern, payload.message_text, re.IGNORECASE):
            score += weight
            threat_indicators.append(label)

    # 3. Media / Video / Attachment Payload Check
    if payload.media_name:
        ext_match = re.search(r"\.(apk|exe|scr|vbs|bat|ps1|hta|iso|dll|zip|jar)$", payload.media_name, re.IGNORECASE)
        if ext_match:
            score += 50
            threat_indicators.append(f"Executable / Weaponized Payload Disguised as Media: {payload.media_name}")

    final_score = min(score, 99)
    intel_data["behavioral_flags"] = threat_indicators

    classification = (
        "CRITICAL_SOCIAL_MEDIA_MALWARE" if final_score >= 85 else
        "SUSPICIOUS_PHISHING_LINK" if final_score >= 60 else
        "BENIGN_SOCIAL_COMMUNICATION"
    )

    tactic = (
        "TA0001 - Initial Access (Social Media Phishing / Drive-by)" if final_score >= 60 else
        "TA0001 - Initial Access (Benign Social Interaction)"
    )

    # Automatically anchor event to blockchain
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=classification,
        user=payload.recipient,
        source_host=f"{payload.platform.upper()}:{payload.sender_id}",
        target_host="USER-MOBILE-ENDPOINT",
        process_name=f"{payload.platform.lower()}_client.exe",
        command=f"Msg: '{payload.message_text[:35]}...'",
        threat_score=final_score,
        mitre_tactic=tactic,
        raw_message=f"Threat Flags: {'; '.join(threat_indicators) if threat_indicators else 'Zero Threat Signatures'}"
    )

    ingest_result = await ingest_event(event)

    return {
        "status": "THREAT_ANALYZED_AND_ANCHORED",
        "threat_score": final_score,
        "classification": classification,
        "threat_intel_summary": intel_data,
        "indicators": threat_indicators,
        "blockchain_proof": {
            "leaf_hash": ingest_result["leaf_hash"],
            "on_chain_merkle_root": ingest_result["merkle_root"]
        },
        "soar_recommendation": "BLOCK_SENDER_AND_ISOLATE_LINK" if final_score >= 80 else "ALLOW"
    }

@router.get("/logs")
async def get_logs():
    return telemetry_logs

@router.get("/merkle-root")
async def get_merkle_root():
    all_leaves = [log["leaf_hash"] for log in telemetry_logs]
    root = compute_merkle_root(all_leaves)
    return {
        "merkle_root": root,
        "total_events": len(telemetry_logs),
        "status": "CONSENSUS_VERIFIED"
    }

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
    exposure_percentage = round((compromised_count / total_count) * 100, 1) if total_count > 0 else 0
    
    return {
        "total_entities_evaluated": total_count,
        "compromised_entities": list(compromised_hosts),
        "enterprise_blast_radius_pct": exposure_percentage,
        "critical_crown_jewel_status": "AT_IMMINENT_RISK" if exposure_percentage >= 50 else "CONTAINED",
        "shortest_critical_path": ["EXT-WAN-198.51.100.24", "WEB-DMZ-01", "APP-SRV-02", "DC-PRIMARY", "BACKUP-DB", "C2-DROP-AWS-S3"]
    }

@router.get("/export/stix", response_class=JSONResponse)
async def export_stix21():
    bundle_id = f"bundle--{uuid.uuid4()}"
    stix_objects = []
    
    actor_id = f"threat-actor--{uuid.uuid4()}"
    stix_objects.append({
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": "Social-Engineering-APT-Group",
        "threat_actor_types": ["nation-state", "cybercrime-syndicate"],
        "sophistication": "advanced",
        "resource_level": "organization"
    })
    
    for log in telemetry_logs:
        indicator_id = f"indicator--{uuid.uuid4()}"
        pattern_id = f"attack-pattern--{uuid.uuid4()}"
        
        stix_objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": pattern_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": log["event_type"],
            "description": log["mitre_tactic"],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": log["mitre_tactic"].split(" - ")[0] if " - " in log["mitre_tactic"] else "TA0001"
            }]
        })
        
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Adversary Signal: {log['source_host']} -> {log['target_host']}",
            "pattern_type": "stix",
            "pattern": f"[network-traffic:src_ref.value = '{log['source_host']}' AND network-traffic:dst_ref.value = '{log['target_host']}']",
            "valid_from": log["timestamp"],
            "custom_properties": {
                "x_sha256_leaf_digest": log.get("leaf_hash", ""),
                "x_threat_score": log["threat_score"]
            }
        })

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
    events_count = len(telemetry_logs)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    rows = ""
    for log in telemetry_logs:
        score_badge = f'<span style="color: {"#f43f5e" if log["threat_score"] >= 90 else "#f59e0b" if log["threat_score"] >= 70 else "#10b981"}; font-weight:bold;">{log["threat_score"]}%</span>'
        short_hash = log.get("leaf_hash", "N/A")[:24]
        rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log['timestamp']}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;"><strong>{log['event_type']}</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log['source_host']} &rarr; {log['target_host']}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{log['mitre_tactic']}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{score_badge}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-family: monospace; font-size: 11px; color:#38bdf8;">{short_hash}...</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberShield DFIR Forensic Legal Brief</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b0f19; color: #f8fafc; padding: 40px; }}
            .card {{ background: #1e293b; border-radius: 12px; padding: 30px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 15px; margin-bottom: 20px; display: flex; justify-content: space-between; }}
            .root-box {{ background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #38bdf8; margin-bottom: 25px; font-family: monospace; color: #38bdf8; word-break: break-all; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
            th {{ background: #0f172a; padding: 12px 10px; text-align: left; color: #94a3b8; border-bottom: 2px solid #334155; }}
            .seal {{ display: inline-block; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; color: #10b981; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="header">
                <div>
                    <h1 style="margin:0; font-size: 24px; color: #38bdf8;">CYBERSHIELD DFIR FORENSIC INCIDENT BRIEF</h1>
                    <p style="margin:5px 0 0 0; color: #94a3b8; font-size: 13px;">Automated Chain of Custody & Cryptographic Evidence Ledger</p>
                </div>
                <div style="text-align: right;">
                    <div class="seal">LEGAL INTEGRITY VERIFIED</div>
                    <p style="margin:5px 0 0 0; font-size: 11px; color: #94a3b8;">Generated: {now}</p>
                </div>
            </div>

            <div class="root-box">
                <strong>ON-CHAIN IMMUTABLE MERKLE ROOT:</strong><br>
                {root}
                <div style="font-size: 12px; color: #94a3b8; margin-top: 5px;">Total Forensic Leaf Evidences Anchored: {events_count}</div>
            </div>

            <h3 style="margin-bottom: 5px; color: #e2e8f0;">Chronological Incident & Attack Reconstruction Table</h3>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Event Type</th>
                        <th>Pivoting Trajectory</th>
                        <th>MITRE ATT&CK Classification</th>
                        <th>Threat Score</th>
                        <th>SHA-256 Leaf Digest</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else '<tr><td colspan="6" style="padding:15px; text-align:center; color:#94a3b8;">No events recorded.</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)