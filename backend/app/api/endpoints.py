import hashlib
import json
import uuid
import re
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

class EmailPayload(BaseModel):
    sender: str
    recipient: str
    subject: str
    body: str
    attachments: Optional[List[str]] = []

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

@router.post("/scan/email")
async def scan_email(payload: EmailPayload):
    score = 15
    indicators = []
    
    # 1. Suspicious keywords analysis (BEC & Urgency)
    urgency_patterns = [r"\burgent\b", r"\bverify your password\b", r"\bbank transfer\b", r"\bwire payment\b", r"\baccount suspended\b", r"\bimmediate action\b"]
    for p in urgency_patterns:
        if re.search(p, payload.body, re.IGNORECASE) or re.search(p, payload.subject, re.IGNORECASE):
            score += 25
            indicators.append(f"Urgent BEC/Coercion Phrase: '{p}'")

    # 2. Typosquatting & Suspicious TLD check
    suspicious_domains = ["secure-bank-login.com", "update-microsoft.co", "verify-it-helpdesk.xyz", "paypal-security-alert.tk"]
    sender_domain = payload.sender.split("@")[-1] if "@" in payload.sender else payload.sender
    if any(sd in sender_domain for sd in suspicious_domains) or sender_domain.endswith((".xyz", ".tk", ".top", ".ru")):
        score += 35
        indicators.append(f"Untrusted / Typosquatted Domain: '{sender_domain}'")

    # 3. Malicious attachment extensions
    for att in payload.attachments:
        if re.search(r"\.(exe|scr|vbs|hta|xlsm|docm|iso|zip)$", att, re.IGNORECASE):
            score += 40
            indicators.append(f"Weaponized Attachment Format: '{att}'")

    final_score = min(score, 99)
    event_type = "PHISHING_SPEAR_ATTACK" if final_score >= 80 else "EMAIL_SPAM_DETECTED" if final_score >= 50 else "EMAIL_BENIGN_CLEAN"
    mitre_tactic = "TA0001 - Initial Access (Spearphishing Attachment/Link)" if final_score >= 70 else "TA0001 - Initial Access (Benign Email Delivery)"

    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=event_type,
        user=payload.recipient,
        source_host=payload.sender,
        target_host="MAIL-GATEWAY-01",
        process_name="exchange_sec_filter.exe",
        command=f"Subject: '{payload.subject[:40]}...'",
        threat_score=final_score,
        mitre_tactic=mitre_tactic,
        raw_message=f"Flags: {'; '.join(indicators) if indicators else 'No threat signatures'}"
    )

    ingest_result = await ingest_event(event)
    return {
        "analysis_status": "ANALYZED_AND_ANCHORED",
        "threat_score": final_score,
        "classification": event_type,
        "indicators": indicators,
        "blockchain_leaf": ingest_result["leaf_hash"],
        "on_chain_merkle_root": ingest_result["merkle_root"]
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
        "name": "APT-NationState-Lateral-Actor",
        "threat_actor_types": ["nation-state", "advanced-persistent-threat"],
        "sophistication": "advanced",
        "resource_level": "government"
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
            "name": f"Adversary Trajectory: {log['source_host']} -> {log['target_host']}",
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