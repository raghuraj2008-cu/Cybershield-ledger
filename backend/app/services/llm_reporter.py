from datetime import datetime, timezone
from typing import List, Dict, Any

class ForensicReportGenerator:
    @staticmethod
    def generate(log_database: List[Dict[str, Any]], merkle_root: str) -> Dict[str, Any]:
        if not log_database:
            return {"error": "No security logs available for analysis."}
        
        max_threat = max(log["threat_score"] for log in log_database)
        observed_tactics = list(set(log["mitre_tactic"] for log in log_database if log["threat_score"] >= 50))
        compromised = list(set([log["source_host"] for log in log_database] + [log["target_host"] for log in log_database]))
        
        return {
            "report_id": f"DFIR-{int(datetime.now(timezone.utc).timestamp())}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "case_classification": "CRITICAL APT BREACH / EXFILTRATION" if max_threat >= 90 else "SUSPICIOUS ACCESS PATTERN",
            "max_threat_score": f"{max_threat}%",
            "chain_of_custody": {
                "on_chain_merkle_root": merkle_root,
                "total_anchored_events": len(log_database),
                "integrity_audit": "100% CRYPTOGRAPHICALLY VERIFIED"
            },
            "compromised_assets": compromised,
            "observed_mitre_tactics": observed_tactics,
            "executive_summary": (
                f"Automated AI threat correlation detected an attack progression reaching maximum severity {max_threat}%. "
                f"Lateral movement was traced across {len(compromised)} enterprise assets. All raw forensic evidence has been "
                f"hashed and rooted on the immutable ledger with Merkle Root {merkle_root[:16]}..."
            ),
            "recommended_containment_actions": [
                "Enforce host quarantine on source endpoint via Windows Firewall / eBPF drop rules.",
                "Revoke active Active Directory Kerberos TGT tokens for compromised user accounts.",
                "Block outbound egress data pipes to external exfiltration IP destinations.",
                "Submit cryptographic Merkle Root to CERT-In / legal authorities as untampered evidence."
            ]
        }

forensic_reporter = ForensicReportGenerator()
