# Module 1 — Data Collection / Input Module

---

## 1. Module Name

**Data Collection and Input Module**

---

## 2. Module Purpose

This module is the **entry point of the entire system**. It is responsible for:

- Attracting attackers through intentionally exposed honeypot services
- Capturing all attacker activity as raw log files
- **Dynamically generating synthetic attack events** each pipeline cycle for continuous live testing
- Generating synthetic red-team traffic during development via `scripts/_traffic.py`

Without this module, the system has no data to process, no patterns to learn from, and nothing to detect.

---

## 3. Problem the Module Solves

Traditional security systems rely on passive sensors or network taps. The challenge is:

- Attackers avoid triggering IDS sensors and don't reveal their full toolchain
- Signature-based systems miss novel attack variants
- Training ML models requires large, labelled, realistic attack datasets

This module solves these problems by:

1. **Deception** — fake services (SSH, Telnet, FTP, HTTP, SMB, MySQL, MSSQL) attract and engage real attackers who believe they are compromising real machines.
2. **Comprehensive logging** — every connection attempt, command, credential, and file download is recorded.
3. **Continuous synthetic generation** — `live/generator.py` creates freshly randomised attack events every 60-second pipeline cycle (new IPs, credentials, commands), so the live pipeline always has data to process regardless of whether live honeypots are active. Unlike a replay mechanism, each generated attack is stateless and unpredictable.

---

## 4. Detailed Explanation of How It Works

### 4.1 Cowrie Honeypot (SSH / Telnet)

Cowrie is a medium-interaction SSH and Telnet honeypot that:
- Accepts any SSH/Telnet connection on port 2222 (Docker-mapped to 22)
- Simulates a realistic shell environment (fake filesystem, fake commands)
- Records every login attempt (credentials tried), shell command entered, file download, and session close event
- Outputs events as **JSON Lines** format to `cowrie.json`

Each Cowrie event includes:
```json
{
  "eventid": "cowrie.login.failed",
  "timestamp": "2026-03-04T12:31:05.123456Z",
  "session": "abc123def456",
  "src_ip": "192.168.1.100",
  "username": "root",
  "password": "admin123"
}
```

Key `eventid` types captured:

| Event ID | Meaning |
|---|---|
| `cowrie.session.connect` | New SSH/Telnet connection |
| `cowrie.client.version` | Client software fingerprint |
| `cowrie.login.failed` | Failed login attempt |
| `cowrie.login.success` | Successful login |
| `cowrie.command.input` | Shell command executed |
| `cowrie.session.file_download` | File downloaded via wget/curl |
| `cowrie.direct-tcpip.request` | Port-forward / tunnel attempt |
| `cowrie.session.closed` | Session ended |

### 4.2 Dionaea Honeypot (Multi-Protocol)

Dionaea is a low-interaction honeypot that captures exploit payloads across many protocols:
- HTTP, FTP, TFTP, SMB, MSSQL, MySQL, MQTT, SIP, Memcached, MongoDB
- Records shellcode injection attempts, malware downloads, RPC exploit attempts
- Outputs text log format to `dionaea.log`

Example Dionaea text log line:

```
[04032026 12:31:05] dionaea.connection.tcp.accept host:'192.168.1.200' port:445 con 0x7f3a12b4c0
[04032026 12:31:06] smb.dcerpc.request host:'192.168.1.200' con 0x7f3a12b4c0
[04032026 12:31:06] shellcode.found con 0x7f3a12b4c0
```

### 4.3 BETH Dataset (Offline / Training Only)

The [BETH dataset](https://github.com/jinxmirror13/BETH_Dataset) provides labelled Linux syscall traces from real systems:
- CSV format: `processId`, `eventName`, `timestamp`, `evil` (0=benign, 1=malicious), `sus`
- Three files: `labelled_training_data.csv`, `labelled_validation_data.csv`, `labelled_testing_data.csv`
- Provides the **benign/malicious ground truth labels** needed for supervised ML training

### 4.4 Synthetic Attack Generator (`live/generator.py`)

`live/generator.py` **generates brand-new**, completely random attack events on every pipeline cycle — it is **not a replayer** of recorded sessions. Each call constructs a freshly synthesised attack with realistic JSON events written to `data/live_raw/`.

**What is randomised each call:**
- Source IP address (random globally-routable IP)
- Protocol: SSH or Telnet (Cowrie), FTP/HTTP/SMB/MSSQL/MySQL (Dionaea)
- Number of login attempts (1–5), credentials drawn from common username/password pools
- Login success probability: 30% chance of `cowrie.login.success`
- Post-login commands: 1–5 random shell commands from a realistic set (`whoami`, `cat /etc/passwd`, `wget`, etc.)
- Occasional file download events (`cowrie.session.file_download`, 20% probability per command)
- Event timestamps: base time 5–30 minutes in the past with realistic inter-event delays

**Attack classification logic (dynamically determined):**
```
login_success AND file_transfer  → MALWARE
login_success AND commands       → EXPLOIT
login_success only               → BRUTE_FORCE
failed logins only               → RECON_PROBE
```

**Output:** JSON Lines written to `data/live_raw/cowrie/YYYY-MM-DD.json` (Cowrie) or `data/live_raw/dionaea/YYYY-MM-DD.json` (Dionaea), one JSON object per event line.

**Optional `random_seed` parameter** — if provided, seeds `random` for reproducible output during testing. In normal operation (`random_seed=None`) each invocation is unpredictable.

This design means every 60-second cycle processes a genuinely distinct attack, preventing pattern habituation and ensuring the live dashboard always shows varied risk levels and attack types.

### 4.5 Attack Traffic Simulator (`scripts/_traffic.py`)

For development and testing, this script generates synthetic SSH/Telnet/HTTP/FTP attacks:
- Uses `paramiko` for SSH brute-force simulation
- Uses raw sockets for Telnet, HTTP probe, FTP, SMB, MSSQL, MySQL
- Configurable duration, count, and sleep interval
- `--local` flag targets localhost-mapped ports instead of Docker hostnames

---

## 4.6 Live Data Inventory — Actual File Sizes and Record Counts

> The following was obtained by inspecting the actual project data directories.

### Raw Data Files

```
data/raw/cowrie/
  cowrie.json     12 events  (raw JSON Lines — 1 real honeypot session captured)

data/raw/dionaea/
  dionaea.log     ~175,888 lines  (text format — 319 sessions across 3 source IPs)

data/beth/raw/
  labelled_training_data.csv    763,141 rows   (~320 MB)
  labelled_validation_data.csv  188,967 rows   (~79 MB)
  labelled_testing_data.csv     188,967 rows   (~79 MB)
  (Total BETH raw: 1,141,075 syscall events → 44,742 windowed sessions)
```

### Real Cowrie Session (from `data/processed/cowrie_events.json`)

This is the actual session captured by the live Cowrie honeypot (internal Docker IP `172.18.0.1`):

```json
{
  "parsed_at": "2026-03-10T13:27:17Z",
  "source_file": "E:\\proactive-cyber-deception\\data\\raw\\cowrie\\cowrie.json",
  "total_sessions": 1,
  "total_events": 12,
  "successful_logins": 1,
  "unique_sources": 1,
  "source_ips": ["172.18.0.1"],
  "sessions": [
    {
      "session_id": "...",
      "src_ip": "172.18.0.1",
      "attack_type": "EXPLOIT",
      "tokens": ["SCAN", "RECON", "RECON", "LOGIN_OK", "RECON", "RECON",
                 "EXEC", "EXEC_FAIL", "EXEC", "EXEC", "SESS_END"]
    }
  ]
}
```

**Key observations:**
- The one captured session originated from **Docker's internal network** (`172.18.0.1`) — this was generated by the `_traffic.py` attacker simulation container, not a real internet attacker
- The session is classified as **EXPLOIT** (contains `LOGIN_OK` + `EXEC` tokens)
- Only 12 events — a short but meaningful attack sequence

### Real Dionaea Sessions (from `data/processed/dionaea_events.json`)

```json
{
  "parsed_at": "2026-02-24T14:00:46Z",
  "total_sessions": 319,
  "total_events": 175,888,
  "unique_sources": 3,
  "sessions": [
    {
      "session_id": "dionaea_0x55dcfae8e4a0",
      "src_ip": "172.18.0.3",
      "attack_type": "BENIGN",
      "label": 0,
      "sus_score": 0.0
    },
    ...
  ]
}
```

**Key observations:**
- 319 sessions from **3 unique source IPs** — all from Docker internal network (simulation)
- 175,888 events across 319 sessions = average **551 events per session** (much longer than Cowrie sessions)
- Some `BENIGN` sessions are included — Dionaea captures even failed/benign connections

### BETH Dataset Scale

```
labelled_training_data.csv   : 763,141 rows
labelled_validation_data.csv : 188,967 rows
labelled_testing_data.csv    : 188,967 rows
─────────────────────────────────────────────
TOTAL                        : 1,141,075 raw syscall events
After windowing              : 44,742 sessions
Class balance                : Benign 38,484 (86%)  Malicious 6,258 (14%)
```

---

## 5. Internal Workflow / Process Flow

```
┌─────────────────────────────────────────────────────────────────┐
│   DATA COLLECTION — TWO PARALLEL PATHS                          │
│                                                                  │
│   PATH A: REAL HONEYPOT CAPTURE (offline training data)         │
│   Internet → port 22/23/80/21/445/3306/1433 → Docker ports      │
│       │                                                          │
│       ├──► Cowrie  → data/raw/cowrie/cowrie.json (JSON Lines)   │
│       └──► Dionaea → data/raw/dionaea/dionaea.log (text)        │
│                                                                  │
│   PATH B: SYNTHETIC GENERATION (live pipeline — every 60s)      │
│   live/generator.py                                              │
│       ├── Generates random Cowrie SSH events                     │
│       │   (random IP, creds, commands, timestamps)               │
│       │   → data/live_raw/cowrie/YYYY-MM-DD.json                 │
│       └── Generates random Dionaea protocol events               │
│           (random IP, protocol, payload)                         │
│           → data/live_raw/dionaea/YYYY-MM-DD.json               │
│                                                                  │
│   PATH C: BETH DATASET (offline training only)                   │
│   data/beth/raw/*.csv  ← labelled Linux syscall traces           │
└─────────────────────────────────────────────────────────────────┘

 scripts/_traffic.py (development / red-team testing)
   └── Sends REAL network packets to Docker-exposed ports
       paramiko SSH brute-force, raw socket Telnet/FTP/SMB/HTTP
       → Triggers real Cowrie/Dionaea log output (PATH A)
```

---

## 6. Key Components / Files Involved

| File | Role |
|---|---|
| `docker/docker-compose.yml` | Defines and launches Cowrie, Dionaea, and MongoDB containers |
| `live/generator.py` | Dynamically generates new synthetic attack events each pipeline cycle |
| `scripts/_traffic.py` | Red-team traffic simulator — sends real SSH/Telnet/HTTP/FTP/SMB packets to honeypot ports |
| `data/raw/cowrie/cowrie.json` | Raw Cowrie JSON Lines log from the real honeypot capture |
| `data/raw/dionaea/dionaea.log` | Raw Dionaea text log from the real honeypot capture |
| `data/beth/raw/labelled_*.csv` | BETH dataset syscall traces (labelled, used for offline training only) |
| `data/live_raw/cowrie/` | Directory where `generator.py` writes synthetic Cowrie JSON events (dated files) |
| `data/live_raw/dionaea/` | Directory where `generator.py` writes synthetic Dionaea JSON events (dated files) |

---

## 7. Important Classes / Functions

```python
def generate_one_attack(source: str = "cowrie", random_seed: int | None = None) -> dict:
    """
    Dynamically generates a NEW, completely random Cowrie SSH/Telnet attack.
    Each call creates fresh events with a random IP, random credentials,
    random commands (if login succeeds), and optional file transfers.
    
    Args:
        source: "cowrie" (parameter kept for runner.py compatibility)
        random_seed: if set, seeds random for reproducible output (testing only)
    
    Returns:
        dict with: session_id, src_ip, num_events, attack_type,
                   login_success, replay_index, total_sessions
    """

def generate_one_dionaea_attack(random_seed: int | None = None) -> dict:
    """
    Dynamically generates a NEW, completely random Dionaea attack.
    Randomly selects protocol (FTP/HTTP/SMB/MSSQL/MySQL), generates
    a random source IP, and writes realistic events to data/live_raw/dionaea/.
    
    Returns:
        dict with: session_id, src_ip, num_events, attack_type,
                   replay_index, total_sessions
    """
```

### `scripts/_traffic.py`

```python
def ssh_attack(host, port, count, sleep):
    """Sends SSH brute-force login attempts using paramiko."""

def telnet_attack(host, port):
    """Sends Telnet connection and command sequence via raw socket."""

def http_probe(host, port):
    """Sends HTTP GET requests probing sensitive paths."""

def ftp_attack(host, port):
    """Sends FTP EXPLOIT sequence (MKD overflow pattern)."""

def smb_probe(host, port):
    """Sends SMB negotiation packet to port 445."""
```

---

## 8. Inputs and Outputs

### Inputs

| Source | Format | Location |
|---|---|---|
| Real attacker connections | Network packets | Ports 22, 23, 80, 21, 445, 3306, 1433 |
| BETH dataset (offline training only) | CSV files | `data/beth/raw/labelled_*.csv` |
| Real Cowrie logs (offline training baseline) | JSON Lines | `data/raw/cowrie/cowrie.json` |
| Real Dionaea logs (offline training baseline) | Text | `data/raw/dionaea/dionaea.log` |

### Outputs

| Output | Format | Location |
|---|---|---|
| Synthetically generated Cowrie events | JSON Lines (dated files) | `data/live_raw/cowrie/YYYY-MM-DD.json` |
| Synthetically generated Dionaea events | JSON Lines (dated files) | `data/live_raw/dionaea/YYYY-MM-DD.json` |
| Real Cowrie session log (honeypot capture) | JSON Lines | `data/raw/cowrie/cowrie.json` |
| Real Dionaea attack log (honeypot capture) | Text | `data/raw/dionaea/dionaea.log` |

---

## 9. Dependencies

| Dependency | Purpose |
|---|---|
| `Docker` / `docker-compose` | Runs Cowrie and Dionaea honeypot containers |
| `paramiko` | SSH client used by `_traffic.py` for brute-force simulation |
| `requests` | HTTP probes used by `_traffic.py` |
| `random` / `uuid` | Core of `generator.py` — random IPs, session IDs, credentials |
| `socket` | Raw TCP/UDP connection simulations in `_traffic.py` |

---

## 10. Interaction with Other Modules

```
Module 1 (Data Collection)
    │
    ├──► Module 2 (Processing / Analysis)
    │       Both live parsers and offline parsers read from this
    │       module's output files (data/raw/, data/live_raw/)
    │
    └──── Module 3 (Core Engine) reads training data built from
           Module 2's processed output, which comes from Module 1's logs
```

---

## 11. Example Flow / Use Case

**Scenario: Synthetically generated SSH brute-force attack (live pipeline cycle)**

```
1. live/runner.py triggers generator.py at the start of a 60-second cycle

2. generator.py creates a new Cowrie SSH attack from scratch:
   - src_ip = "83.142.37.201"   (random globally-routable IP)
   - session_id = "gen_a4f2e8b1"  (random UUID fragment)
   - Generates events:
     cowrie.session.connect   (src_ip: 83.142.37.201)
     cowrie.client.version    (SSH-2.0-OpenSSH_7.4p1)
     cowrie.client.kex        (hassh: 4831029...)
     cowrie.login.failed × 3  (root/123456, admin/password, pi/raspberry)
     cowrie.login.success     (ubuntu/qwerty)   ← 30% success rate
     cowrie.command.input     (whoami)
     cowrie.command.input     (cat /etc/passwd)
     cowrie.session.file_download  (http://malware.com/evil.sh → /tmp/evil.sh)
     cowrie.session.closed

3. Events written as JSON Lines to:
   data/live_raw/cowrie/2026-04-15.json  (appended)

4. live/parse_cowrie.py reads new lines from offset,
   emits a session record: attack_type="MALWARE"

5. Module 2 (sequence_builder.py) buffers events → emits token sequence:
   [COWRIE] SCAN RECON RECON LOGIN_ATT LOGIN_ATT LOGIN_ATT LOGIN_OK
            EXEC EXEC FILE_XFER SESS_END

6. Module 3 (inference.py) scores the sequence:
   DistilBERT: attack_prob=0.9821 → MALICIOUS
   XLNet: perplexity=1.23, predicted_next_token=SESS_END, anomaly=0.965
   Combined severity=2.73 → risk_level=CRITICAL
```

---

## 12. Configuration Details

### Docker Compose (`docker/docker-compose.yml`)

```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "2222:2222"    # SSH
      - "2323:2323"    # Telnet
    volumes:
      - ./data/raw/cowrie:/cowrie/var/log/cowrie

  dionaea:
    image: dinotools/dionaea:latest
    ports:
      - "21:21"        # FTP
      - "80:80"        # HTTP
      - "445:445"      # SMB
      - "3306:3306"    # MySQL
      - "1433:1433"    # MSSQL
    volumes:
      - ./data/raw/dionaea:/opt/dionaea/var/log/dionaea

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
```

### Traffic Simulator (`scripts/_traffic.py`)

```bash
# Target Docker-internal hosts
python scripts/_traffic.py --duration 300 --count 500 --sleep 0.5

# Target localhost-mapped ports (no Docker network needed)
python scripts/_traffic.py --local --duration 300 --count 200
```

---

## 13. Implementation Notes

- **Cowrie uses JSON Lines** (one JSON object per line, newline-delimited). The parser must handle partial lines gracefully for incremental live parsing.
- **Dionaea's timestamp format (`DDMMYYYY HH:MM:SS`) does NOT sort lexicographically** — it must be parsed and sorted by actual `datetime` objects (this is handled correctly in `scripts/parse_dionaea.py`).
- **The generator creates dated raw files** (`data/live_raw/cowrie/YYYY-MM-DD.json`) — new events are always appended to today's file. The live parser reads only from today's file and tracks its byte offset in MongoDB so it never re-processes the same lines.
- **`_traffic.py` uses raw `socket`** for Telnet (replacing the deprecated `telnetlib` which was removed in Python 3.13). SSH brute-force uses `paramiko`.
- **Every generated attack is stateless** — `generator.py` does not track what it previously generated. The random seed (`random.seed()` at import time) is freshly initialised each interpreter session, so no two runs produce the same sequence. Pass `random_seed=<int>` only for deterministic testing.
- **`relay_index` and `total_sessions` in the generator return dict are mock values** (`random.randint(0, 99)` and `random.randint(50, 150)` respectively) — they exist purely for compatibility with `runner.py` logging format and carry no functional meaning.
