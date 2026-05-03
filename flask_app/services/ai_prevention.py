"""
flask_app/services/ai_prevention.py — Groq LLaMA-powered prevention and mitigation advice.

How it works:
  1. Builds a rich, attack-specific prompt from the full prediction context:
       attack_type, risk_level, token sequence (with meanings), predicted_next_token,
       attack_probability, trajectory, combined severity, and stage reached.
  2. Sends the prompt to Groq (LLaMA) with a strict JSON schema instruction.
  3. Parses and validates the structured JSON response.
  4. Caches the response in MongoDB `ai_prevention_cache` (keyed by attack_type + risk + next_token).
  5. Falls back to clean, static advice on any error.

Environment variable required:
  GROQ_API_KEY=<your_api_key>

No API key → immediate fallback (silent).
API error   → falls back to static templates, logs warning.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta

from shared_db import get_collection

# ── Groq SDK import ───────────────────────────────────────────────────────────
_log = logging.getLogger(__name__)

try:
    from groq import Groq
    _GROQ_OK = True
except ImportError:
    _GROQ_OK = False

# ── Config ────────────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
CACHE_HOURS  = 24

# ── Token vocabulary descriptions (for richer AI context) ─────────────────────
_TOKEN_MEANINGS: dict[str, str] = {
    "SCAN":         "network/port scan — attacker mapping the target surface",
    "LOGIN_ATT":    "failed authentication attempt — brute-force in progress",
    "LOGIN_OK":     "successful authentication — attacker has gained access",
    "EXEC":         "command executed — attacker running shell commands on the host",
    "FILE_XFER":    "file transfer — possible malware upload or data exfiltration",
    "FILE_WRITE":   "file written — attacker modifying or creating files on disk",
    "FILE_DEL":     "file deleted — possible evidence destruction",
    "FILE_MOD":     "file modified — configuration tampering or persistence mechanism",
    "NET_CONN":     "network connection established — C2 or lateral movement",
    "NET_OPEN":     "socket opened — attacker establishing new network channel",
    "NET_SEND":     "data sent over network — possible exfiltration",
    "PRIV_ESC":     "privilege escalation — attacker attempting to gain root/admin",
    "PRIV_CHG":     "privilege change — escalation or lateral movement",
    "PROC_EXEC":    "process executed — attacker spawning new processes",
    "PROC_CREATE":  "process created — possible malware or backdoor launch",
    "TUNNEL":       "network tunnel created — covert channel for C2 or exfiltration",
    "MALWARE":      "malware activity detected — malicious binary or script running",
    "EXPLOIT":      "exploitation pattern — attacker exploiting a vulnerability",
    "SESS_END":     "session terminated gracefully",
    "PERM_CHG":     "permission change — attacker altering file/directory permissions",
    "MEM_ALLOC":    "memory allocation — possible shellcode or buffer overflow prep",
    "MEM_PROT":     "memory protection change — DEP/ASLR bypass attempt",
    "IPC":          "inter-process communication — lateral movement between processes",
    "FILE_ACC":     "file accessed — reconnaissance of sensitive files",
    "FILE_OPEN":    "file opened — reading system/config files",
    "NET_CLOSE":    "network connection closed",
    "NET_BIND":     "network bind operation — attacker opening a listener port",
    "NET_ACCEPT":   "accepted inbound connection — service or reverse shell",
    "NET_RECV":     "data received — possible C2 command received",
    "NET_LISTEN":   "port listener created — backdoor or reverse shell",
    "NET_SOCK":     "raw socket created — stealth scanning or spoofing",
    "PROC_EXIT":    "process exited",
    "PROC_SIG":     "process signal sent — possible kill or injection attempt",
    "FILE_CREAT":   "file created — possible persistence artifact",
    "FILE_CLOSE":   "file handle closed",
    "SLEEP":        "sleep/delay — attacker timing out detection windows",
    "SYNC":         "sync operation",
    "MEM_MAP":      "memory mapped — file-less execution technique",
    "EXEC_FAIL":    "command execution failed — possible permission block",
    "NET_CONNECT":  "outbound connection — C2 callback or exfiltration",
    "EXPLOITATION": "active exploitation attempt against a service vulnerability",
    "RECON":        "reconnaissance activity — fingerprinting services or users",
}

def _describe_token(t: str) -> str:
    return _TOKEN_MEANINGS.get(t, t)


# ── Attack stage inference ────────────────────────────────────────────────────
def _infer_stage(tokens: list[str], next_token: str) -> str:
    """Return a human-readable description of the attack stage reached."""
    if not tokens:
        return "No tokens observed — possible connection probing only."

    last = tokens[-1]
    token_set = set(tokens)

    if last in {"MALWARE", "FILE_XFER"} or next_token == "MALWARE":
        return "Malware deployment stage — attacker is uploading or executing malicious code."
    if last in {"PRIV_ESC", "PRIV_CHG"} or next_token in {"PRIV_ESC", "PRIV_CHG"}:
        return "Privilege escalation stage — attacker is attempting to gain elevated access."
    if last in {"TUNNEL", "NET_CONN", "NET_CONNECT"} or next_token == "TUNNEL":
        return "Command-and-control stage — attacker establishing covert communication channels."
    if "LOGIN_OK" in token_set and "EXEC" in token_set:
        return "Post-exploitation stage — attacker has authenticated and is executing commands."
    if "LOGIN_OK" in token_set:
        return "Initial access achieved — attacker has successfully authenticated."
    if token_set & {"LOGIN_ATT"} and "LOGIN_OK" not in token_set:
        return f"Brute-force stage — {tokens.count('LOGIN_ATT') if hasattr(tokens, 'count') else 'multiple'} failed login attempts, no access yet."
    if last in {"SCAN", "RECON", "FILE_ACC", "FILE_OPEN"}:
        return "Reconnaissance stage — attacker is mapping the target, no access gained yet."
    if last in {"FILE_WRITE", "FILE_MOD", "FILE_CREAT", "PERM_CHG"}:
        return "Persistence stage — attacker is modifying the system for continued access."
    return f"Active attack stage — last observed action: {last} ({_describe_token(last)})."


# ── Groq client singleton ─────────────────────────────────────────────────────
_groq_client = None

def _get_groq_client():
    """Return a cached Groq client (reuses the underlying HTTP connection pool)."""
    global _groq_client
    if _groq_client is None and _GROQ_OK and GROQ_API_KEY:
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a senior cybersecurity incident responder and threat analyst with deep expertise in:
- Honeypot-based deception systems and attacker behaviour analysis
- Machine learning-based intrusion detection (DistilBERT, XLNet)
- MITRE ATT&CK framework and real-world incident response
- Network forensics, malware analysis, and host hardening

You are analysing a live attack session detected by a proactive cyber deception system.
You will be given the exact sequence of attack tokens observed, their meanings, the attack
stage reached, and what the ML models predict the attacker will do next.

Your task: generate DETAILED, SPECIFIC, TECHNICALLY ACCURATE prevention and mitigation advice.

RULES — follow these exactly:
1. Your advice MUST reference the specific tokens seen (e.g. "Since LOGIN_OK was observed, \
credentials are compromised — rotate them immediately").
2. Provide detailed prevention techniques covering immediate actions, tactical response, and hardening.
3. Each technique must be complete and specific — not vague hints.
   BAD:  "Harden authentication"
   GOOD: "Disable SSH password authentication in /etc/ssh/sshd_config (PasswordAuthentication no); \
restart sshd immediately."
4. For CRITICAL risk, focus on decisive actions — isolate, block, revoke, contain.
5. Format prevention techniques as detailed bullet points or narrative.
6. Return ONLY a valid JSON object — no markdown, no code fences, no extra keys.

JSON schema (respond with exactly this structure):
{
  "trigger_explanation": "<2-3 sentences: what happened, what stage>",
  "prevention_summary": "<line 1>\\n<line 2>",
  "prevention_techniques": "<detailed prevention techniques covering multiple approaches>"
}
"""

# ── User prompt ───────────────────────────────────────────────────────────────
_USER_PROMPT_TEMPLATE = """\
=== HONEYPOT ATTACK SESSION — {risk_level} RISK ===

Attack Classification
  Type:              {attack_type}
  Risk Level:        {risk_level}
  DistilBERT Verdict: {distilbert_label} (confidence: {attack_prob:.1%})
  Combined Severity:  {combined_severity:.3f}

Attack Stage Reached
  {stage_description}

Token Sequence Observed ({token_count} tokens, in order):
{tokens_annotated}

Predicted Next Action (XLNet): {predicted_next_token}
  Meaning: {next_token_meaning}
{next_token_warning}
Attack Trajectory (XLNet): {xlnet_trajectory}

=== TASK ===
Analyse this specific attack session. Reference the actual tokens seen above.
Generate detailed, specific, technical prevention and mitigation advice.
The attacker has reached the stage described above — advise accordingly.
"""


def _build_prompt(
    attack_type: str,
    risk_level: str,
    tokens: list,
    next_token: str,
    label: str,
    attack_prob: float,
    trajectory: str,
    severity: float,
) -> str:
    """Build the full user prompt from prediction context."""
    # Annotated token list — each token with its meaning
    if tokens:
        annotated_lines = []
        for i, t in enumerate(tokens[:25], 1):
            meaning = _describe_token(t)
            annotated_lines.append(f"  {i:2}. {t:<16} → {meaning}")
        tokens_annotated = "\n".join(annotated_lines)
        if len(tokens) > 25:
            tokens_annotated += f"\n  ... and {len(tokens) - 25} more tokens"
    else:
        tokens_annotated = "  (no tokens recorded — session may have been too short)"

    stage_description = _infer_stage(tokens, next_token)
    next_token_meaning = _describe_token(next_token) if next_token else "unknown"

    # High-value next-token warnings
    _NEXT_TOKEN_ALERTS = {
        "FILE_XFER":  "⚠ FILE TRANSFER predicted — malware download or data exfiltration imminent.",
        "EXEC":       "⚠ COMMAND EXECUTION predicted — remote code execution (RCE) risk.",
        "PRIV_ESC":   "⚠ PRIVILEGE ESCALATION predicted — full system compromise risk.",
        "TUNNEL":     "⚠ TUNNEL predicted — covert C2 channel or lateral movement risk.",
        "MALWARE":    "⚠ MALWARE deployment predicted — immediate containment required.",
        "LOGIN_OK":   "⚠ SUCCESSFUL LOGIN predicted — brute-force attack about to succeed.",
        "NET_CONNECT":"⚠ OUTBOUND CONNECTION predicted — C2 callback or exfiltration risk.",
        "FILE_DEL":   "⚠ FILE DELETION predicted — possible evidence destruction.",
    }
    next_token_warning = _NEXT_TOKEN_ALERTS.get(next_token, "")
    if next_token_warning:
        next_token_warning = f"  {next_token_warning}\n"

    return _USER_PROMPT_TEMPLATE.format(
        attack_type        = attack_type,
        risk_level         = risk_level,
        distilbert_label   = label,
        attack_prob        = attack_prob,
        combined_severity  = severity,
        stage_description  = stage_description,
        token_count        = len(tokens),
        tokens_annotated   = tokens_annotated,
        predicted_next_token = next_token or "UNKNOWN",
        next_token_meaning   = next_token_meaning,
        next_token_warning   = next_token_warning,
        xlnet_trajectory     = trajectory or "Not determined",
    )


# ── Cache helpers ─────────────────────────────────────────────────────────────
def _cache_key(attack_type: str, risk_level: str, next_token: str) -> str:
    return f"{attack_type}_{risk_level}_{next_token or 'NONE'}"


def _get_cached(attack_type: str, risk_level: str, next_token: str) -> dict | None:
    col = get_collection("ai_prevention_cache")
    key = _cache_key(attack_type, risk_level, next_token)
    doc = col.find_one({"cache_key": key})
    if not doc:
        return None
    try:
        cached_at = datetime.fromisoformat(doc.get("cached_at", "").replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - cached_at < timedelta(hours=CACHE_HOURS):
            return doc.get("prevention")
    except (ValueError, TypeError):
        pass
    return None


def _save_cache(attack_type: str, risk_level: str, next_token: str, prevention: dict) -> None:
    key = _cache_key(attack_type, risk_level, next_token)
    col = get_collection("ai_prevention_cache")
    col.update_one(
        {"cache_key": key},
        {"$set": {
            "cache_key":   key,
            "attack_type": attack_type,
            "risk_level":  risk_level,
            "next_token":  next_token,
            "prevention":  prevention,
            "cached_at":   datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )


# ── Groq API call ─────────────────────────────────────────────────────────────
def _call_groq(prompt: str) -> str:
    """Call Groq API and return raw text response."""
    client = _get_groq_client()
    if client is None:
        raise ValueError("Groq SDK or API Key missing")

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        response_format={"type": "json_object"},
        temperature=0.2,          # lower temp = more consistent, accurate advice
        max_tokens=1024,          # enough for detailed but not bloated responses
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    )
    return response.choices[0].message.content


# ── Static fallback (when Groq is unavailable) ────────────────────────────────
def _fallback(attack_type: str, risk_level: str, next_token: str) -> dict:
    """Return clean, concise static prevention advice when the Groq API is unavailable."""
    _SIMPLE_ACTIONS = {
        "access": ["Block source IP. Lock accounts.", "Enable MFA. Enforce policy.", "Deploy fail2ban. Zero-trust."],
        "network": ["Rate-limit. Enable logging.", "Move SSH port. Port knock.", "IP reputation. Auto-block."],
        "host": ["Disable pwd auth. Restart SSH.", "Password policy. Complexity.", "Audit accounts. Remove defaults."]
    }
    
    _SEVERITY_ACTIONS = {
        "EXPLOITED": ["Isolate host. Disconnect VPN.", "Audit accounts. Revoke excess.", "Least-privilege model."],
        "MALWARE": ["Quarantine host. Limit services.", "Block C2. Filter DNS.", "TLS inspection."],
        "TUNNEL": ["Kill tunnels. Block ports.", "Audit VPN. Detect anomalies.", "Zero-trust access."],
        "SCAN": ["Log IP. Watchlist.", "Review services. Close ports.", "Firewall audit. Deny-default."],
        "RECON": ["Log & flag source.", "Monitor IP range.", "Attack-surface review."]
    }
    _TEMPLATES = {
        "BRUTE_FORCE": {
            "trigger": f"{risk_level} risk brute-force attack detected — repeated login failures observed.",
            "summary": "Block source IP at firewall. Enable MFA on all services.\nRate-limit connections. Disable password auth, enforce key-based access.",
        },
        "EXPLOIT": {
            "trigger": f"{risk_level} risk exploitation attempt detected — vulnerability being targeted.",
            "summary": "Isolate host from network immediately. Apply emergency security patch.\nBlock outbound connections. Audit and revoke excess account privileges.",
        },
        "MALWARE": {
            "trigger": f"{risk_level} risk malware activity detected — malicious code may be running.",
            "summary": "Quarantine host and capture memory dump for forensics.\nBlock all C2 domains, terminate malicious processes, re-image system.",
        },
        "RECONNAISSANCE": {
            "trigger": f"{risk_level} risk reconnaissance detected — attacker is mapping services.",
            "summary": "Log source IP and add to watchlist. Rate-limit probe responses.\nDisable unnecessary services. Deploy honeytokens and deception layers.",
        },
        "SCAN": {
            "trigger": f"{risk_level} risk port scan detected — attacker mapping open ports.",
            "summary": "Block source IP at perimeter firewall. Review open ports and close unnecessary ones.\nEnable port knocking, IPS scan detection. Deny by default policy.",
        },
        "TUNNEL": {
            "trigger": f"{risk_level} risk tunnelling detected — covert channel may be established.",
            "summary": "Kill tunnel processes. Block suspicious ports and DNS queries.\nDeploy deep packet inspection (DPI). Enable SSL/TLS inspection for tunnels.",
        },
    }

    t = _TEMPLATES.get(attack_type) or _TEMPLATES["SCAN"]
    prefix = "⚠ URGENT — " if risk_level in {"HIGH", "CRITICAL"} else ""

    return {
        "trigger_explanation": t["trigger"],
        "prevention_summary":  prefix + t["summary"],
        "source": "fallback",
    }


# ── Response parser ───────────────────────────────────────────────────────────
def _parse_response(raw: str) -> dict:
    """Parse and validate JSON response against expected schema."""
    text = raw.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
        text = text.rsplit("```", 1)[0].strip()

    data = json.loads(text)

    required = {"trigger_explanation", "prevention_summary", "prevention_techniques"}
    if not required.issubset(data.keys()):
        raise ValueError(f"Missing keys: {required - data.keys()}")

    return data


# ── Main public function ───────────────────────────────────────────────────────
def get_ai_prevention(prediction_doc: dict) -> dict:
    """
    Generate AI-powered prevention advice for a prediction document.

    When Groq API is available, returns detailed prevention techniques:
    Returns a prevention dict:
    {
        "trigger_explanation": str,     — detailed explanation of what happened
        "prevention_summary":  str,     — two-line quick summary
        "prevention_techniques": str,   — detailed prevention techniques and mitigation actions
        "source": "groq" | "groq_cached" | "fallback"
    }
    
    When Groq is unavailable, returns simplified fallback with just summary.
    """
    attack_type = prediction_doc.get("attack_type", "SCAN")
    risk_level  = prediction_doc.get("risk_level",  "LOW")
    next_token  = prediction_doc.get("predicted_next_token", "")
    tokens      = prediction_doc.get("tokens", [])
    attack_prob = prediction_doc.get("attack_prob", 0.0)
    label       = prediction_doc.get("distilbert_label", "BENIGN")
    trajectory  = prediction_doc.get("xlnet_trajectory", "")
    severity    = prediction_doc.get("combined_severity", 0.0)

    # 1. Try cache first
    cached = _get_cached(attack_type, risk_level, next_token)
    if cached:
        cached["source"] = "groq_cached"
        return cached

    # 2. No key or SDK unavailable → fallback immediately
    if not GROQ_API_KEY or not _GROQ_OK:
        return _fallback(attack_type, risk_level, next_token)

    # 3. Build the detailed prompt
    prompt = _build_prompt(
        attack_type=attack_type,
        risk_level=risk_level,
        tokens=tokens,
        next_token=next_token,
        label=label,
        attack_prob=attack_prob,
        trajectory=trajectory,
        severity=severity,
    )

    # 4. Call Groq API
    try:
        raw        = _call_groq(prompt)
        prevention = _parse_response(raw)
        prevention["source"] = "groq"
        _save_cache(attack_type, risk_level, next_token, prevention)
        return prevention

    except json.JSONDecodeError as e:
        _log.warning("[AI_PREVENTION] JSON parse error: %s", e)
    except ValueError as e:
        _log.warning("[AI_PREVENTION] Schema error: %s", e)
    except Exception as e:
        _log.warning("[AI_PREVENTION] Groq API error: %s", e)

    return _fallback(attack_type, risk_level, next_token)
