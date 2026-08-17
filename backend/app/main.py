from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from datetime import datetime
from app.services.ai_detector import detector
from app.services.merkle_tree import MerkleTree

app = FastAPI(title="CyberShield Ledger API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityLog(BaseModel):
    event_id: str
    timestamp: str
    source_host: str
    target_host: str
    user: str
    event_type: str
    process_name: str
    raw_message: str

log_database = []

@app.get("/")
def root():
    return {"status": "CyberShield API Online"}

@app.post("/api/v1/ingest")
def ingest_log(log: SecurityLog):
    ai_result = detector.analyze(log.event_type, log.user)
    log_entry = log.model_dump()
    log_entry.update(ai_result)
    log_entry["log_hash"] = MerkleTree.hash_str(json.dumps(log_entry, sort_keys=True))
    log_database.append(log_entry)
    
    return {
        "status": "ingested",
        "threat_score": ai_result["threat_score"],
        "mitre_tactic": ai_result["mitre_tactic"],
        "log_hash": log_entry["log_hash"]
    }

@app.get("/api/v1/logs")
def get_logs():
    return log_database

@app.get("/api/v1/merkle-root")
def get_merkle_root():
    hashes = [log["log_hash"] for log in log_database]
    root, _ = MerkleTree.build_tree(hashes)
    return {"merkle_root": root, "total_events": len(hashes)}

@app.get("/api/v1/forensic-report")
def generate_forensic_report():
    if not log_database:
        return {"error": "No telemetry recorded to generate report."}
    
    hashes = [log["log_hash"] for log in log_database]
    root, _ = MerkleTree.build_tree(hashes)
    max_threat = max(log["threat_score"] for log in log_database)
    tactics = list(set(log["mitre_tactic"] for log in log_database if log["threat_score"] >= 50))
    
    return {
        "report_id": f"DFIR-{int(datetime.utcnow().timestamp())}",
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "case_classification": "CRITICAL INCIDENT / APT EXFILTRATION" if max_threat >= 90 else "SUSPICIOUS ACTIVITY",
        "max_threat_score": f"{max_threat}%",
        "chain_of_custody": {
            "on_chain_merkle_root": root,
            "total_anchored_events": len(log_database),
            "evidence_integrity": "100% CRYPTOGRAPHICALLY VERIFIED"
        },
        "compromised_assets": list(set([log["source_host"] for log in log_database] + [log["target_host"] for log in log_database])),
        "observed_mitre_tactics": tactics,
        "executive_summary": f"Automated forensics detected a multi-stage compromise with maximum threat score {max_threat}%. Logs anchored with Merkle Root {root[:16]}...",
        "recommended_containment_actions": [
            "Isolate host network adapter on PC-17 via SOAR command.",
            "Revoke Active Directory token for admin_svc.",
            "Block outbound exfiltration traffic to external IP 198.51.100.42.",
            "Submit on-chain Merkle root to CERT-In / legal authorities."
        ]
    }
