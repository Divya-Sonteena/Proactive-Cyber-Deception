"""
scripts/mitre_mapping.py — MITRE ATT&CK Technique Lookup Table

Maps attack tokens produced by Cowrie/Dionaea parsers to one or more
MITRE ATT&CK technique objects.  Each entry is a list of dicts so a
single token can map to multiple techniques (e.g. EXEC maps to both
T1059 and T1543).

Structure of each technique dict
─────────────────────────────────
  technique_id   : str   — ATT&CK ID (e.g. "T1046")
  technique_name : str   — Human-readable name
  tactic         : str   — ATT&CK tactic phase
  url            : str   — MITRE ATT&CK navigator URL

Usage
─────
from mitre_mapping import get_mitre_techniques, MITRE_MAP
techs = get_mitre_techniques(["SCAN", "LOGIN_ATT", "EXEC"])
# → [{"technique_id": "T1046", ...}, {"technique_id": "T1110", ...}, ...]
"""

from __future__ import annotations

# ── Full mapping ───────────────────────────────────────────────────────────────
MITRE_MAP: dict[str, list[dict]] = {

    # ── Reconnaissance / Scanning ──────────────────────────────────────────────
    "SCAN": [
        {
            "technique_id":   "T1046",
            "technique_name": "Network Service Discovery",
            "tactic":         "Discovery",
            "url":            "https://attack.mitre.org/techniques/T1046/",
        }
    ],
    "RECON": [
        {
            "technique_id":   "T1592",
            "technique_name": "Gather Victim Host Information",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1592/",
        },
        {
            "technique_id":   "T1595",
            "technique_name": "Active Scanning",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1595/",
        },
    ],
    "RECON_FINGERPRINT": [
        {
            "technique_id":   "T1592",
            "technique_name": "Gather Victim Host Information",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1592/",
        }
    ],
    "RECON_PASSIVE": [
        {
            "technique_id":   "T1591",
            "technique_name": "Gather Victim Org Information",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1591/",
        }
    ],
    "RECON_PROBE": [
        {
            "technique_id":   "T1595",
            "technique_name": "Active Scanning",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1595/",
        }
    ],
    "RECON_TUNNEL": [
        {
            "technique_id":   "T1572",
            "technique_name": "Protocol Tunneling",
            "tactic":         "Command and Control",
            "url":            "https://attack.mitre.org/techniques/T1572/",
        }
    ],
    "RECONNAISSANCE": [
        {
            "technique_id":   "T1592",
            "technique_name": "Gather Victim Host Information",
            "tactic":         "Reconnaissance",
            "url":            "https://attack.mitre.org/techniques/T1592/",
        }
    ],

    # ── Credential Access ──────────────────────────────────────────────────────
    "LOGIN_ATT": [
        {
            "technique_id":   "T1110",
            "technique_name": "Brute Force",
            "tactic":         "Credential Access",
            "url":            "https://attack.mitre.org/techniques/T1110/",
        }
    ],
    "LOGIN_OK": [
        {
            "technique_id":   "T1078",
            "technique_name": "Valid Accounts",
            "tactic":         "Defense Evasion / Persistence",
            "url":            "https://attack.mitre.org/techniques/T1078/",
        }
    ],
    "BRUTE_FORCE": [
        {
            "technique_id":   "T1110",
            "technique_name": "Brute Force",
            "tactic":         "Credential Access",
            "url":            "https://attack.mitre.org/techniques/T1110/",
        }
    ],

    # ── Execution ──────────────────────────────────────────────────────────────
    "EXEC": [
        {
            "technique_id":   "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic":         "Execution",
            "url":            "https://attack.mitre.org/techniques/T1059/",
        }
    ],
    "EXEC_FAIL": [
        {
            "technique_id":   "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic":         "Execution",
            "url":            "https://attack.mitre.org/techniques/T1059/",
        }
    ],

    # ── File / Payload Transfer ────────────────────────────────────────────────
    "FILE_XFER": [
        {
            "technique_id":   "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic":         "Command and Control",
            "url":            "https://attack.mitre.org/techniques/T1105/",
        }
    ],
    "FILE_TRANSFER": [
        {
            "technique_id":   "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic":         "Command and Control",
            "url":            "https://attack.mitre.org/techniques/T1105/",
        }
    ],

    # ── Tunnelling / C2 ────────────────────────────────────────────────────────
    "TUNNEL": [
        {
            "technique_id":   "T1572",
            "technique_name": "Protocol Tunneling",
            "tactic":         "Command and Control",
            "url":            "https://attack.mitre.org/techniques/T1572/",
        },
        {
            "technique_id":   "T1090",
            "technique_name": "Proxy",
            "tactic":         "Command and Control",
            "url":            "https://attack.mitre.org/techniques/T1090/",
        },
    ],

    # ── Malware / Exploitation ─────────────────────────────────────────────────
    "MALWARE": [
        {
            "technique_id":   "T1204",
            "technique_name": "User Execution",
            "tactic":         "Execution",
            "url":            "https://attack.mitre.org/techniques/T1204/",
        },
        {
            "technique_id":   "T1587",
            "technique_name": "Develop Capabilities: Malware",
            "tactic":         "Resource Development",
            "url":            "https://attack.mitre.org/techniques/T1587/001/",
        },
    ],
    "EXPLOITATION": [
        {
            "technique_id":   "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic":         "Initial Access",
            "url":            "https://attack.mitre.org/techniques/T1190/",
        }
    ],
    "EXPLOIT": [
        {
            "technique_id":   "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic":         "Initial Access",
            "url":            "https://attack.mitre.org/techniques/T1190/",
        }
    ],
}


# ── Public API ─────────────────────────────────────────────────────────────────

def get_mitre_techniques(tokens: list[str]) -> list[dict]:
    """
    Given a list of attack tokens, return a deduplicated list of
    MITRE ATT&CK technique dicts covering all observed tokens.

    Deduplication is by technique_id — the first-seen entry wins.
    """
    seen: set[str] = set()
    result: list[dict] = []
    for token in tokens:
        for tech in MITRE_MAP.get(token, []):
            tid = tech["technique_id"]
            if tid not in seen:
                seen.add(tid)
                result.append(tech)
    return result


def get_tactics_summary(tokens: list[str]) -> list[str]:
    """Return deduplicated tactic names observed across tokens."""
    seen: set[str] = set()
    tactics: list[str] = []
    for token in tokens:
        for tech in MITRE_MAP.get(token, []):
            tactic = tech["tactic"]
            if tactic not in seen:
                seen.add(tactic)
                tactics.append(tactic)
    return tactics
