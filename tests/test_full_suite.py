import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"

def print_test(name, passed, detail=""):
    badge = "[\033[92mPASS\033[0m]" if passed else "[\033[91mFAIL\033[0m]"
    print(f"{badge} {name} {f'- {detail}' if detail else ''}")
    if not passed:
        sys.exit(1)

def run_suite():
    print("\n" + "="*60)
    print("🛡️  CYBERSHIELD LEDGER ENTERPRISE 2.0 - E2E INTEGRATION SUITE")
    print("="*60 + "\n")

    # 1. Reset Baseline State
    r = requests.post(f"{BASE_URL}/clear")
    print_test("1. Session Baseline Reset", r.status_code == 200 and r.json().get("status") == "CLEARED")

    # 2. Ingest Safe Benign Event
    benign_event = {
        "event_id": "test-benign-001",
        "timestamp": "2026-08-21T00:00:00Z",
        "event_type": "FILE_DOWNLOAD_EVENT",
        "user": "analyst_user",
        "source_host": "INTERNET-INGRESS",
        "target_host": "WORKSTATION-01",
        "process_name": "chrome.exe",
        "command": "Ingress: safe_report.pdf",
        "threat_score": 30,
        "mitre_tactic": "TA0001 - Initial Access",
        "raw_message": "Safe benign document download"
    }
    r = requests.post(f"{BASE_URL}/ingest", json=benign_event)
    data = r.json()
    print_test("2. Benign Event Ingestion & Leaf Hashing", r.status_code == 200 and "leaf_hash" in data, f"Leaf: {data.get('leaf_hash', '')[:16]}...")

    # 3. Verify Blast Radius Nominal Status
    r = requests.get(f"{BASE_URL}/analytics/blast-radius")
    br = r.json()
    print_test("3. Subnet Blast Radius (Nominal)", br.get("enterprise_blast_radius_pct") == 0.0, f"Exposure: {br.get('enterprise_blast_radius_pct')}%")

    # 4. Ingest Phishing Email Scan
    phishing_payload = {
        "sender": "admin-alert@verify-it-helpdesk.xyz",
        "recipient": "cfo@internal.corp",
        "subject": "URGENT: Immediate Action Required - Account Suspended",
        "body": "Your account has been suspended. Please verify your password immediately to avoid wire payment disruption.",
        "attachments": ["invoice_macro_payload.xlsm"]
    }
    r = requests.post(f"{BASE_URL}/scan/email", json=phishing_payload)
    em = r.json()
    print_test("4. Spearphishing Heuristic Detection", em.get("threat_score") >= 90 and em.get("classification") == "PHISHING_SPEAR_ATTACK", f"Score: {em.get('threat_score')}%")

    # 5. Ingest Lateral APT Attack Event
    apt_event = {
        "event_id": "test-apt-001",
        "timestamp": "2026-08-21T00:01:00Z",
        "event_type": "LSASS_MEMDUMP",
        "user": "SYSTEM",
        "source_host": "APP-SRV-02",
        "target_host": "DC-PRIMARY",
        "process_name": "procdump.exe",
        "command": "procdump -ma lsass.exe lsass.dmp",
        "threat_score": 94,
        "mitre_tactic": "TA0006 - Credential Access",
        "raw_message": "Unauthorized LSASS memory handle access"
    }
    r = requests.post(f"{BASE_URL}/ingest", json=apt_event)
    print_test("5. Lateral APT Critical Event Ingestion", r.status_code == 200)

    # 6. Verify Honeytoken Deception Trip
    r = requests.get(f"{BASE_URL}/deception/canaries")
    canaries = r.json()
    dc_tripped = any(c["host"] == "DC-PRIMARY" and "TRIPPED" in c["status"] for c in canaries)
    print_test("6. Active Deception Canary Autonomous Trigger", dc_tripped, "CNRY-LSASS-901 Tripped on DC-PRIMARY")

    # 7. Verify Merkle Root State Consensus
    r = requests.get(f"{BASE_URL}/merkle-root")
    mr = r.json()
    print_test("7. Cryptographic Merkle Root Consensus", mr.get("status") == "CONSENSUS_VERIFIED" and len(mr.get("merkle_root", "")) == 64, f"Root: {mr.get('merkle_root', '')[:20]}...")

    # 8. Verify STIX 2.1 Threat Intel Export
    r = requests.get(f"{BASE_URL}/export/stix")
    stix = r.json()
    print_test("8. OASIS STIX 2.1 Threat Bundle Generation", stix.get("type") == "bundle" and len(stix.get("objects", [])) > 0, f"Objects: {len(stix.get('objects', []))}")

    # 9. Verify NIST SP 800-86 Legal Brief Endpoint
    r = requests.get(f"{BASE_URL}/generate-report")
    print_test("9. NIST SP 800-86 Forensic Brief Generator", r.status_code == 200 and "CYBERSHIELD DFIR FORENSIC INCIDENT BRIEF" in r.text)

    print("\n" + "="*60)
    print("✅  ALL 9 DEFENSE VALIDATION CHECKS PASSED (100% RELIABILITY)")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_suite()