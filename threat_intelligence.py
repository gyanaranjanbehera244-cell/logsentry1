"""
LOGSENTRY Threat Intelligence & MITRE ATT&CK Framework Mapping
Provides enterprise-grade threat taxonomy, MITRE technique correlation, and kill chain staging.
"""

MITRE_TECHNIQUES = {
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing (Brute Force)",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries repeatedly guess passwords to compromise credentials.",
        "severity": "Medium",
        "color": "#f59e0b"
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying (Distributed)",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries cycle passwords across many accounts or source IPs to evade account lockouts.",
        "severity": "High",
        "color": "#ef4444"
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion & Initial Access",
        "tactic_id": "TA0005",
        "description": "Adversaries obtain and abuse credentials of existing accounts following successful brute-force or credential stuffing.",
        "severity": "High",
        "color": "#ef4444"
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation (Privilege Escalation)",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries manipulate accounts to maintain or elevate access permissions.",
        "severity": "High",
        "color": "#dc2626"
    },
    "T1530": {
        "id": "T1530",
        "name": "Data from Cloud / Crown Jewels",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "description": "Adversaries access sensitive data repositories, confidential databases, or storage containers.",
        "severity": "Critical",
        "color": "#991b1b"
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries steal sensitive data by accessing crown-jewel assets and exfiltrating them.",
        "severity": "Critical",
        "color": "#7f1d1d"
    },
    "T1087": {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries attempt logins across numerous user identifiers to enumerate valid domain/system accounts.",
        "severity": "Medium",
        "color": "#f59e0b"
    }
}

KILL_CHAIN_STAGES = [
    {"stage": "1. Recon & Probing", "code": "RECON", "icon": "🔍", "desc": "IP activity scans, account probing"},
    {"stage": "2. Credential Access", "code": "AUTH_ATTACK", "icon": "🔑", "desc": "Brute-force or password spraying"},
    {"stage": "3. Initial Access", "code": "BREACH", "icon": "🚪", "desc": "Successful authentication after failures"},
    {"stage": "4. Privilege Escalation", "code": "PRIV_ESC", "icon": "⚡", "desc": "Elevation to admin/system role"},
    {"stage": "5. Actions on Objectives", "code": "EXFIL", "icon": "🎯", "desc": "Sensitive database or file access"}
]

def map_event_to_kill_chain(event_name):
    """Maps a security event name to its Kill Chain stage and MITRE technique."""
    e = str(event_name).lower().strip()
    if e == "failed":
        return {
            "stage": "2. Credential Access",
            "mitre": MITRE_TECHNIQUES["T1110.001"],
            "badge": "Failed Login",
            "color": "#f87171"
        }
    elif e == "success":
        return {
            "stage": "3. Initial Access",
            "mitre": MITRE_TECHNIQUES["T1078"],
            "badge": "Auth Success",
            "color": "#34d399"
        }
    elif e == "privilege_change":
        return {
            "stage": "4. Privilege Escalation",
            "mitre": MITRE_TECHNIQUES["T1098"],
            "badge": "Privilege Change",
            "color": "#fbbf24"
        }
    elif e == "sensitive_access":
        return {
            "stage": "5. Actions on Objectives",
            "mitre": MITRE_TECHNIQUES["T1530"],
            "badge": "Sensitive Access",
            "color": "#c084fc"
        }
    return {
        "stage": "1. Recon & Probing",
        "mitre": MITRE_TECHNIQUES["T1087"],
        "badge": "General Event",
        "color": "#94a3b8"
    }
