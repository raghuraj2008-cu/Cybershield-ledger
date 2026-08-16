class ThreatDetector:
    def __init__(self):
        self.failure_history = {}

    def analyze(self, event_type: str, user: str) -> dict:
        event_clean = event_type.upper()
        user_clean = user.upper()
        is_failure = 1 if "FAILURE" in event_clean else 0
        
        self.failure_history[user_clean] = self.failure_history.get(user_clean, 0) + is_failure
        attempts = self.failure_history[user_clean]

        # Multi-Vector Threat Evaluation
        if "EXFILTRATION" in event_clean:
            score = 98
            mitre_tactic = "TA0010 - Exfiltration (Data Stolen)"
            is_anomaly = True
        elif "PRIVILEGE" in event_clean or "ESCALATION" in event_clean:
            score = 92
            mitre_tactic = "TA0004 - Privilege Escalation (Token Manipulation)"
            is_anomaly = True
        elif "ADMIN" in user_clean and is_failure:
            score = min(96, 60 + (attempts * 12))
            mitre_tactic = "TA0006 - Credential Access (Targeting Admin)"
            is_anomaly = True
        elif is_failure:
            score = min(88, 30 + (attempts * 15))
            mitre_tactic = "TA0001 - Initial Access (Brute Force Spray)"
            is_anomaly = score > 50
        else:
            score = 5
            mitre_tactic = "TA0007 - Discovery (Normal Activity)"
            is_anomaly = False

        return {
            "threat_score": score,
            "is_anomaly": is_anomaly,
            "mitre_tactic": mitre_tactic
        }

detector = ThreatDetector()
