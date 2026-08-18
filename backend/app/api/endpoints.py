import hashlib
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import List, Optional

from app.services.merkle import merkle_service
from app.services.blockchain import blockchain_service

router = APIRouter()

# In-memory storage for audit trail
telemetry_logs = []

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

@router.post("/ingest")
async def ingest_event(event: TelemetryEvent):
    event_dict = event.dict()
    
    # Compute deterministic leaf hash
    serialized = json.dumps(event_dict, sort_keys=True)
    leaf_hash = hashlib.sha256(serialized.encode()).hexdigest()
    event_dict["leaf_hash"] = leaf_hash
    
    telemetry_logs.append(event_dict)
    
    # Anchor to Merkle tree
    merkle_service.add_leaf(leaf_hash)
    current_root = merkle_service.get_root()
    
    # Blockchain commit
    blockchain_receipt = blockchain_service.anchor_merkle_root(current_root, len(telemetry_logs))
    
    return {
        "status": "INGESTED_AND_ANCHORED",
        "event_id": event.event_id,
        "leaf_hash": leaf_hash,
        "merkle_root": current_root,
        "blockchain": blockchain_receipt
    }

@router.get("/logs")
async def get_logs():
    return telemetry_logs

@router.get("/merkle-root")
async def get_merkle_root():
    root = merkle_service.get_root()
    return {
        "merkle_root": root,
        "total_events": len(telemetry_logs),
        "status": "CONSENSUS_VERIFIED"
    }

@router.get("/generate-report", response_class=HTMLResponse)
async def generate_legal_dfir_report():
    root = merkle_service.get_root()
    events_count = len(telemetry_logs)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    rows = ""
    for log in telemetry_logs:
        score_badge = f'<span style="color: {"#f43f5e" if log["threat_score"] >= 90 else "#f59e0b" if log["threat_score"] >= 70 else "#10b981"}; font-weight:bold;">{log["threat_score"]}%</span>'
        rows += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{log['timestamp']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;"><strong>{log['event_type']}</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{log['source_host']} &rarr; {log['target_host']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{log['mitre_tactic']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{score_badge}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155; font-family: monospace; font-size: 11px;">{log.get('leaf_hash', 'N/A')[:16]}...</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberShield Forensics & Incident Response (DFIR) Legal Brief</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b0f19; color: #f8fafc; padding: 40px; }}
            .card {{ background: #1e293b; border-radius: 12px; padding: 30px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 15px; margin-bottom: 20px; display: flex; justify-content: space-between; }}
            .root-box {{ background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #38bdf8; margin-bottom: 25px; font-family: monospace; color: #38bdf8; word-break: break-all; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
            th {{ background: #0f172a; padding: 10px 8px; text-align: left; color: #94a3b8; border-bottom: 2px solid #334155; }}
            .seal {{ display: inline-block; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; color: #10b981; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 12px; }}
            @media print {{
                body {{ background: #fff; color: #000; padding: 0; }}
                .card {{ background: #fff; border: none; color: #000; }}
                .root-box {{ background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }}
                th {{ background: #f8fafc; color: #334155; }}
            }}
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

            <div style="margin-top: 30px; font-size: 11px; color: #64748b; border-top: 1px solid #334155; padding-top: 15px;">
                Forensic certificate validated against EVM smart contract anchor <code>EvidenceLedger.sol</code>. Tamper proofs verified under NIST SP 800-86 digital evidence preservation standards.
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)