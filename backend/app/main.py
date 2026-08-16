from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
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
