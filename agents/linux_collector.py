import time
import uuid
import requests
import socket
from datetime import datetime, timezone

BACKEND_URL = "http://127.0.0.1:8000/api/v1/ingest"
HOSTNAME = socket.gethostname()

def stream_audit_events():
    print("🛡️ CyberShield Linux Telemetry Collector Active...")
    simulated_events = [
        {"user": "root", "event": "PRIVILEGE_ESCALATION", "process": "sudo", "msg": "User added to sudoers group"},
        {"user": "apache", "event": "DATA_EXFILTRATION", "process": "curl", "msg": "Outbound HTTP pipe to suspicious IP"}
    ]
    
    for item in simulated_events:
        payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_host": HOSTNAME,
            "target_host": "SRV-PROD-01",
            "user": item["user"],
            "event_type": item["event"],
            "process_name": item["process"],
            "raw_message": item["msg"]
        }
        try:
            res = requests.post(BACKEND_URL, json=payload, timeout=2)
            print(f"[+] Linux Telemetry Sent: {item['event']} -> Threat Score: {res.json().get('threat_score')}%")
        except Exception as e:
            print(f"[-] Backend offline or unreachable: {e}")
        time.sleep(2)

if __name__ == "__main__":
    stream_audit_events()
