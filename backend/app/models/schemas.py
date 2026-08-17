from pydantic import BaseModel
from typing import Optional, Dict, Any, List

class SecurityLogCreate(BaseModel):
    event_id: str
    timestamp: str
    source_host: str
    target_host: str
    user: str
    event_type: str
    process_name: str
    raw_message: str

class SecurityLogResponse(SecurityLogCreate):
    threat_score: int
    is_anomaly: bool
    mitre_tactic: str
    log_hash: str

class MerkleRootResponse(BaseModel):
    merkle_root: str
    total_events: int

class DFIRReportResponse(BaseModel):
    report_id: str
    timestamp_utc: str
    case_classification: str
    max_threat_score: str
    chain_of_custody: Dict[str, Any]
    compromised_assets: List[str]
    observed_mitre_tactics: List[str]
    executive_summary: str
    recommended_containment_actions: List[str]
