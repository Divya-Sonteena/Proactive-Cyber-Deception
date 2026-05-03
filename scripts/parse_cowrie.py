#!/usr/bin/env python3
"""
Parse Cowrie honeypot JSON logs and extract structured attack events.

Reads Cowrie's JSON Lines log format and:
- Groups events by session ID
- Maps attack events to behavioural tokens via token_definitions
- Extracts session metadata (IP, username, duration, commands)
- Captures failed-login credentials and hassh fingerprints
- Generates structured output for ML training

Input:  data/raw/cowrie/cowrie.json       (JSON Lines)
Output: data/processed/cowrie_events.json (JSON)
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from token_definitions import get_token

# Max commands stored per session in the report (None = unlimited)
MAX_COMMANDS = None

# Cowrie eventid → semantic event type
# get_token() then maps these semantic names to canonical short tokens.
COWRIE_EVENT_TYPES = {
    'cowrie.session.connect':       'SCAN',
    'cowrie.client.version':        'RECONNAISSANCE',
    'cowrie.client.kex':            'RECONNAISSANCE',
    'cowrie.client.size':           'RECONNAISSANCE',
    'cowrie.session.params':        'RECONNAISSANCE',
    'cowrie.login.failed':          'LOGIN_ATTEMPT',
    'cowrie.login.success':         'LOGIN_SUCCESS',
    'cowrie.command.input':         'EXECUTE',
    'cowrie.command.failed':        'EXECUTE_FAILED',
    'cowrie.session.file_download': 'FILE_TRANSFER',
    'cowrie.session.file_upload':   'FILE_TRANSFER',
    'cowrie.direct-tcpip.request':  'TUNNEL',
    'cowrie.log.closed':            'SESSION_END',
    'cowrie.session.closed':        'SESSION_END',
}


def _create_session_template() -> dict:
    """Return a blank session accumulator."""
    return {
        'events':          [],
        'tokens':          [],
        'src_ip':          None,
        'all_timestamps':  [],
        'start_time':      None,
        'end_time':        None,
        'username':        None,
        'success':         False,
        'commands':        [],
        'attempted_creds': [],
        'hassh':           None,
        'arch':            None,
    }


def parse_cowrie_logs(log_file_path: str) -> dict:
    """Parse Cowrie JSON Lines log and group events by session.

    Args:
        log_file_path: Path to cowrie.json
    Returns:
        dict of sessions keyed by session_id
    """
    sessions    = defaultdict(_create_session_template)
    error_count = 0

    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                error_count += 1
                continue

            session_id = event.get('session')
            if not session_id:
                continue

            session = sessions[session_id]

            ts = event.get('timestamp')
            if ts:
                session['all_timestamps'].append(ts)

            if session['src_ip'] is None:
                session['src_ip'] = event.get('src_ip')

            event_id   = event.get('eventid')
            event_type = COWRIE_EVENT_TYPES.get(event_id)

            if event_type:
                # SESSION_END is deduplicated — only the first occurrence is kept
                # to avoid inflating the token sequence with repeated SESS_END.
                already_ended = (
                    event_type == 'SESSION_END'
                    and any(e['type'] == 'SESSION_END' for e in session['events'])
                )
                if not already_ended:
                    session['events'].append({'type': event_type, 'timestamp': ts})
                    token = get_token(event_type)
                    # Apply the same dedup guard to the token list
                    if token != 'SESS_END' or 'SESS_END' not in session['tokens']:
                        session['tokens'].append(token)

            # ── Per-event metadata extraction ─────────────────────────────────
            if event_id == 'cowrie.login.success':
                session['username'] = event.get('username')
                session['success']  = True

            elif event_id == 'cowrie.login.failed':
                uname = event.get('username')
                if uname is not None:
                    session['attempted_creds'].append({
                        'username': uname,
                        'password': event.get('password'),
                    })

            elif event_id == 'cowrie.command.input':
                cmd = event.get('input', '').strip()
                if cmd:
                    session['commands'].append(cmd)

            elif event_id == 'cowrie.client.kex' and session['hassh'] is None:
                session['hassh'] = event.get('hassh')

            elif event_id == 'cowrie.session.params' and session['arch'] is None:
                session['arch'] = event.get('arch')

    if error_count > 0:
        print(f'[!] Skipped {error_count} malformed lines')

    # Derive start/end from the full timestamp pool (robust to log ordering)
    for session in sessions.values():
        ts_list = session.pop('all_timestamps')
        if ts_list:
            session['start_time'] = min(ts_list)
            session['end_time']   = max(ts_list)

    return dict(sessions)


def _recon_signals(session: dict) -> frozenset:
    """Return a frozenset of recon signal names observed in the session.

    Signals:
        'hassh'      — SSH client fingerprint captured (client.kex)
        'arch'       — attacker OS architecture captured (session.params)
        'version'    — SSH client version banner seen (client.version)
        'tunnel'     — direct-tcpip probe detected
        'exec_probe' — command attempted without a successful login
    """
    signals   = set()
    event_ids = {e.get('type') for e in session.get('events', [])}

    if session.get('hassh'):        signals.add('hassh')
    if session.get('arch'):         signals.add('arch')
    if 'RECONNAISSANCE' in event_ids: signals.add('version')
    if 'TUNNEL' in event_ids:       signals.add('tunnel')
    if 'EXECUTE_FAILED' in event_ids and 'LOGIN_SUCCESS' not in event_ids:
        signals.add('exec_probe')

    return frozenset(signals)


def classify_attack_type(session: dict) -> str:
    """Classify attack type from session behaviour.

    Priority (high → low):
      MALWARE           login success + commands + file transfer
      EXPLOIT           login success + commands/exec-failed, or login only
      BRUTE_FORCE       login attempts with no success
      RECON_FINGERPRINT hassh/arch/version harvested, no auth
      RECON_TUNNEL      direct-tcpip probe, no auth
      RECON_PROBE       pre-auth command injection attempt
      RECON_PASSIVE     banner/version seen, nothing deeper
      MIXED             >2 distinct token types, no clearer category
      SCAN              bare connect only
    """
    tokens = session.get('tokens', [])

    has_login_attempt = 'LOGIN_ATT' in tokens
    has_login_success = 'LOGIN_OK'  in tokens
    has_commands      = 'EXEC'      in tokens
    has_exec_failed   = 'EXEC_FAIL' in tokens
    has_file_transfer = 'FILE_XFER' in tokens
    has_recon         = 'RECON'     in tokens
    has_tunnel        = 'TUNNEL'    in tokens

    # ── Post-login ────────────────────────────────────────────────────────────
    if has_login_success and has_commands and has_file_transfer:
        return 'MALWARE'
    if has_login_success and (has_commands or has_exec_failed):
        return 'EXPLOIT'
    if has_login_success:
        return 'EXPLOIT'

    # ── Failed auth → brute force ─────────────────────────────────────────────
    if has_login_attempt:
        return 'BRUTE_FORCE'

    # ── Recon sub-types (no auth attempted) ───────────────────────────────────
    signals = _recon_signals(session)

    if {'hassh', 'arch'} & signals or ('version' in signals and 'arch' in signals):
        return 'RECON_FINGERPRINT'
    if 'tunnel' in signals or has_tunnel:
        return 'RECON_TUNNEL'
    if 'exec_probe' in signals or has_exec_failed:
        return 'RECON_PROBE'
    if has_recon or signals:
        return 'RECON_PASSIVE'

    # ── Mixed / default ───────────────────────────────────────────────────────
    if len(set(tokens)) > 2:
        return 'MIXED'
    return 'SCAN'


def calculate_session_duration(session: dict) -> float:
    """Return session duration in seconds, or 0 if timestamps are missing."""
    if not (session['start_time'] and session['end_time']):
        return 0
    try:
        start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
        end   = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
        return (end - start).total_seconds()
    except (ValueError, AttributeError):
        return 0


def generate_report(
    sessions:     dict,
    output_file:  str  = None,
    source_file:  str  = None,
    max_commands: int  = MAX_COMMANDS,
) -> dict:
    """Build a structured report from parsed sessions and optionally write to JSON.

    Args:
        sessions:     Parsed sessions from parse_cowrie_logs()
        output_file:  Path to save JSON report (optional)
        source_file:  Original log path written to metadata (optional)
        max_commands: Max commands per session in output (None = all)
    Returns:
        dict with statistics and per-session details
    """
    all_events     = [e for s in sessions.values() for e in s['events']]
    unique_src_ips = list({s['src_ip'] for s in sessions.values() if s['src_ip']})

    report = {
        'parsed_at':       datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_file':     str(source_file) if source_file else None,
        'total_sessions':  len(sessions),
        'total_events':    len(all_events),
        'successful_logins': sum(1 for s in sessions.values() if s['success']),
        'unique_sources':  len(unique_src_ips),
        'source_ips':      unique_src_ips,
        'sessions':        [],
    }

    for session_id, sd in sessions.items():
        cmds = sd['commands']
        report['sessions'].append({
            'session_id':         session_id,
            'src_ip':             sd['src_ip'],
            'start_time':         sd['start_time'],
            'end_time':           sd['end_time'],
            'duration_seconds':   calculate_session_duration(sd),
            'username':           sd['username'],
            'login_success':      sd['success'],
            'hassh':              sd['hassh'],
            'arch':               sd['arch'],
            'num_events':         len(sd['events']),
            'num_commands':       len(cmds),
            'commands_executed':  cmds if max_commands is None else cmds[:max_commands],
            'num_login_attempts': len(sd['attempted_creds']),
            'attempted_creds':    sd['attempted_creds'],
            'event_types':        [e['type'] for e in sd['events']],
            'event_tokens':       sd['tokens'],
            'attack_type':        classify_attack_type(sd),
        })

    report['sessions'].sort(key=lambda x: x['start_time'] or '')

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f'[DONE] Report saved → {Path(output_file).name}')

    return report


def main():
    """Run the Cowrie log parsing pipeline."""
    log_path = (
        Path(sys.argv[1]) if len(sys.argv) > 1
        else Path(__file__).parent.parent / 'data' / 'raw' / 'cowrie' / 'cowrie.json'
    )

    print(f'[INFO] Parsing: {log_path}')

    try:
        sessions = parse_cowrie_logs(str(log_path))
    except FileNotFoundError:
        print('[FAIL] File not found')
        sys.exit(1)

    if not sessions:
        print('[!] No sessions found')
        return

    output_file = Path(__file__).parent.parent / 'data' / 'processed' / 'cowrie_events.json'
    report = generate_report(sessions, str(output_file), source_file=log_path)

    print(f"\n[DONE] Sessions: {report['total_sessions']}  Events: {report['total_events']}")


if __name__ == '__main__':
    main()
