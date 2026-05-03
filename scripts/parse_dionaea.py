#!/usr/bin/env python3
"""
Parse Dionaea honeypot logs and extract attack events.

Reads Dionaea's text log format and:
- Parses timestamps and event types from log messages
- Groups events into sessions by connection handle (con 0x...)
- Maps attack events to behavioural tokens
- Generates structured output for ML training

Input:  data/raw/dionaea/dionaea.log       (text format)
Output: data/processed/dionaea_events.json (JSON)
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from token_definitions import TOKEN_SHORTCUTS

# ── Event-type classification tables ─────────────────────────────────────────

# Named incident pattern → event type  (highest priority — most precise)
INCIDENT_EVENT_TYPES = [
    ('dionaea.download.complete',     'FILE_TRANSFER'),
    ('dionaea.download.offer',        'MALWARE'),
    ('dionaea.upload.request',        'FILE_TRANSFER'),
    ('dionaea.connection.tcp.accept', 'SCAN'),   # connection accepted: port scan / probe
    ('dionaea.connection.udp.accept', 'SCAN'),
    ('dionaea.connection.tcp.listen', 'SCAN'),
    ('dionaea.connection.link',       'SCAN'),
    ('shellcode.found',               'EXPLOITATION'),
    ('smb.dcerpc.request',            'EXPLOITATION'),
    ('mysql.login',                   'EXPLOITATION'),
    ('mssql.login',                   'EXPLOITATION'),
]

# Port number → event type  (checked when no named incident matched)
PORT_EVENT_TYPES = {
    21:    'FILE_TRANSFER',   # FTP
    22:    'SCAN',            # SSH
    23:    'SCAN',            # Telnet
    25:    'RECONNAISSANCE',  # SMTP
    42:    'RECONNAISSANCE',  # WINS
    69:    'FILE_TRANSFER',   # TFTP
    80:    'RECONNAISSANCE',  # HTTP
    135:   'EXPLOITATION',    # MS-RPC
    443:   'RECONNAISSANCE',  # HTTPS
    445:   'EXPLOITATION',    # SMB
    1433:  'EXPLOITATION',    # MSSQL
    1723:  'EXPLOITATION',    # PPTP
    1883:  'EXPLOITATION',    # MQTT
    3306:  'EXPLOITATION',    # MySQL
    5060:  'RECONNAISSANCE',  # SIP
    9100:  'EXPLOITATION',    # Printer
    11211: 'EXPLOITATION',    # Memcached
    27017: 'EXPLOITATION',    # MongoDB
}

# Compiled regex patterns for log-line parsing
_TIMESTAMP_RE  = re.compile(r'\[(\d{8} \d{2}:\d{2}:\d{2})\]')
_CONNECTION_RE = re.compile(r'\bcon (0x[0-9a-fA-F]+)\b')
_PORT_RE       = re.compile(r'\bport (\d+)\b')


def _extract_ip(line: str) -> str | None:
    """Return the first IPv4 address found in *line*, or None."""
    m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    return m.group(0) if m else None


def _extract_connection_id(line: str) -> str | None:
    """Return the Dionaea connection handle ('0x...') from *line*, or None."""
    m = _CONNECTION_RE.search(line)
    return m.group(1) if m else None


def _extract_event_type(line: str) -> str | None:
    """Classify a log line using three-tier priority.

    Tier 1 — Named incident strings (most precise, checked first)
    Tier 2 — Port number found in the line
    Tier 3 — Broad keyword fallback (least precise)
    """
    line_lower = line.lower()

    # Tier 1: exact incident pattern
    for pattern, etype in INCIDENT_EVENT_TYPES:
        if pattern in line_lower:
            return etype

    # Tier 2: well-known port number
    m = _PORT_RE.search(line)
    if m:
        port = int(m.group(1))
        if port in PORT_EVENT_TYPES:
            return PORT_EVENT_TYPES[port]

    # Tier 3: keyword fallback
    for keyword, etype in [
        ('malware',    'MALWARE'),
        ('exploit',    'EXPLOITATION'),
        ('download',   'FILE_TRANSFER'),
        ('upload',     'FILE_TRANSFER'),
        ('tftp',       'FILE_TRANSFER'),
        ('http',       'RECONNAISSANCE'),
        ('smb',        'EXPLOITATION'),
        ('ftp',        'FILE_TRANSFER'),
        ('connection', 'SCAN'),
    ]:
        if keyword in line_lower:
            return etype

    return None


def parse_dionaea_logs(log_file_path: str) -> list[dict]:
    """Parse Dionaea text log and return a list of classified events.

    Args:
        log_file_path: Path to dionaea.log
    Returns:
        Events sorted chronologically, each with timestamp, parsed_time,
        connection_id, type, message, and src_ip fields.
    """
    events = []

    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = _TIMESTAMP_RE.match(line)
            if not m:
                continue

            event_type = _extract_event_type(line)
            if not event_type:
                continue

            timestamp = m.group(1)
            try:
                parsed_time = datetime.strptime(timestamp, '%d%m%Y %H:%M:%S')
            except ValueError:
                parsed_time = None

            events.append({
                'timestamp':     timestamp,
                'parsed_time':   parsed_time,
                'connection_id': _extract_connection_id(line),
                'type':          event_type,
                'message':       line[:150],
                'src_ip':        _extract_ip(line),
            })

    # Sort by actual datetime — avoids the DDMMYYYY lexical ordering bug
    events.sort(key=lambda x: x['parsed_time'] or datetime.min)
    return events


def aggregate_events(events: list[dict]) -> dict:
    """Group events into sessions by Dionaea connection handle.

    Each unique 'con 0x...' handle becomes one session, mirroring
    Cowrie's session-ID approach.  Events with no handle (startup /
    module-load lines) are collected under 'dionaea_startup'.

    Args:
        events: Pre-sorted events from parse_dionaea_logs()
    Returns:
        dict of sessions keyed by session_id
    """
    def _empty_session() -> dict:
        return {
            'events':      [],
            'tokens':      [],
            'start_time':  None,
            'end_time':    None,
            'event_types': set(),
            'src_ips':     set(),
        }

    sessions   = {}
    con_ip_map = {}              # connection_id → src_ip (inherited by later events)
    startup_id = 'dionaea_startup'

    for event in events:
        if event['parsed_time'] is None:
            continue

        con_id = event.get('connection_id')
        src_ip = event.get('src_ip')

        if con_id:
            # Propagate the source IP to later events on the same connection
            if src_ip:
                con_ip_map[con_id] = src_ip
            else:
                src_ip = con_ip_map.get(con_id)

            session_id = f'dionaea_{con_id}'
        else:
            session_id = startup_id

        if session_id not in sessions:
            sessions[session_id] = _empty_session()
        session = sessions[session_id]

        if src_ip and con_id:
            session['src_ips'].add(src_ip)

        # Store the event without parse-internal fields
        storable = {k: v for k, v in event.items()
                    if k not in ('parsed_time', 'connection_id')}
        session['events'].append(storable)
        session['event_types'].add(event['type'])
        # TOKEN_SHORTCUTS maps event-type strings to canonical tokens;
        # fall back to the raw type string if no mapping exists.
        session['tokens'].append(TOKEN_SHORTCUTS.get(event['type'], event['type']))

        if session['start_time'] is None:
            session['start_time'] = event['timestamp']
        session['end_time'] = event['timestamp']

    return sessions


def classify_attack_type(session: dict) -> str:
    """Classify attack type from session token sequence.

    Priority (high → low):
      MALWARE        malware download/offer detected
      EXPLOITATION   RPC/SMB/DB exploit or shellcode
      FILE_TRANSFER  file transfer without a malware marker
      RECONNAISSANCE HTTP/HTTPS/SIP/SMTP/WINS probe
      MIXED          two or more distinct token types
      SCAN           pure port-scan connections only

    Note: FILE_TRANSFER events are tokenised as FILE_XFER by token_definitions,
    and RECONNAISSANCE events become RECON — so those are the strings checked.
    """
    token_set = set(session.get('tokens', []))

    if 'MALWARE'      in token_set: return 'MALWARE'
    if 'EXPLOITATION' in token_set: return 'EXPLOITATION'
    if 'FILE_XFER'    in token_set: return 'FILE_TRANSFER'
    if 'RECON'        in token_set: return 'RECONNAISSANCE'
    if len(token_set) >= 2:         return 'MIXED'
    return 'SCAN'


def calculate_session_duration(session: dict) -> float:
    """Return session duration in seconds from DDMMYYYY HH:MM:SS timestamps."""
    if not (session.get('start_time') and session.get('end_time')):
        return 0
    try:
        fmt   = '%d%m%Y %H:%M:%S'
        start = datetime.strptime(session['start_time'], fmt)
        end   = datetime.strptime(session['end_time'],   fmt)
        return max((end - start).total_seconds(), 0)
    except (ValueError, AttributeError):
        return 0


def generate_report(sessions: dict, source_file: str = None) -> dict:
    """Build a Cowrie-compatible structured report of all Dionaea sessions.

    Output schema matches cowrie_events.json for unified ML pipeline ingestion.

    Args:
        sessions:    Sessions from aggregate_events()
        source_file: Original log path written to metadata (optional)
    Returns:
        dict with metadata and per-session records
    """
    def _to_iso8601(timestamp_str: str) -> str | None:
        """Convert DDMMYYYY HH:MM:SS to ISO 8601 UTC format."""
        if not timestamp_str:
            return None
        try:
            dt = datetime.strptime(timestamp_str, '%d%m%Y %H:%M:%S')
            return dt.replace(tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except (ValueError, AttributeError):
            return None

    all_src_ips = set()
    for s in sessions.values():
        all_src_ips.update(s['src_ips'])

    report = {
        'parsed_at':      datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_file':    str(source_file) if source_file else None,
        'total_sessions': len(sessions),
        'total_events':   sum(len(s['events']) for s in sessions.values()),
        'unique_sources': len(all_src_ips),
        'sessions':       [],
    }

    for session_id, session in sorted(sessions.items()):
        src_ips = list(session['src_ips'])
        report['sessions'].append({
            'session_id':       session_id,
            'src_ip':           src_ips[0] if src_ips else None,
            'start_time':       _to_iso8601(session['start_time']),
            'end_time':         _to_iso8601(session['end_time']),
            'duration_seconds': calculate_session_duration(session),
            'num_events':       len(session['events']),
            'event_types':      [e['type'] for e in session['events']],
            'event_tokens':     session['tokens'],
            'attack_type':      classify_attack_type(session),
        })

    report['sessions'].sort(key=lambda x: x['start_time'] or '')
    return report


def main():
    """Parse Dionaea logs → aggregate events → write dionaea_events.json."""
    log_file = (
        Path(__file__).parent.parent / 'data' / 'raw' / 'dionaea' / 'dionaea.log'
    )

    print(f'[INFO] Parsing: {log_file}')

    events   = parse_dionaea_logs(str(log_file))
    sessions = aggregate_events(events)
    report   = generate_report(sessions, source_file=log_file)

    output_file = Path(__file__).parent.parent / 'data' / 'processed' / 'dionaea_events.json'
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print(f'[DONE] Report saved → {output_file.name}')
    print(f"\n[DONE] Sessions: {report['total_sessions']}  Events: {report['total_events']}")


if __name__ == '__main__':
    main()
