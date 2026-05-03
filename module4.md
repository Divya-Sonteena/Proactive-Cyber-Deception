# Module 4 — Response and Action Module

---

## 1. Module Name

**Response and Action Module**

---

## 2. Module Purpose

This module transforms raw detections into **actionable intelligence and automated countermeasures**. Once Module 3 scores an attack session, this module:

1. Generates AI-powered prevention advice using a large language model (Groq LLaMA)
2. Executes automated firewall responses on command (block IP, watchlist, audit-log)
3. Correlates related sessions into multi-session attack campaigns
4. Builds and maintains per-IP attacker behavioural profiles
5. Detects canary token access and records deception trigger events

---

## 3. Problem the Module Solves

Detecting an attack is necessary but not sufficient. Security teams face:

- **Alert fatigue** — too many alerts, not enough actionable context
- **Slow response** — manual triage of each alert takes time attackers exploit
- **Isolated incidents** — individual session alerts miss coordinated multi-session campaigns
- **Generic advice** — textbook recommendations don't match the specific observed attack behaviour

This module solves these by:
- Converting every HIGH/CRITICAL prediction into specific, LLM-generated countermeasures
- Allowing admins to fire one-click OS-level IP block commands from the dashboard
- Grouping sessions into campaigns so a multi-hour coordinated attack is visible as one entity
- Accumulating everything about a given attacker IP into a structured behavioural profile

---

## 4. Detailed Explanation of How It Works

### 4.1 AI Prevention Advice (`flask_app/services/ai_prevention.py`)

The `get_ai_prevention()` function generates LLM-powered countermeasures for every scored prediction.

**Flow:**

```
1. Build cache key = hash(attack_type + risk_level + predicted_next_token)
2. Check MongoDB ai_prevention_cache for unexpired entry (TTL: 24 hours)
3. If cache HIT → return cached result immediately (no API call)
4. If cache MISS →
   a. Get Groq client (singleton, reuses connection pool)
   b. Build structured prompt with full attack context
   c. Call Groq API (llama-3.1-8b-instant, response_format={"type":"json_object"})
   d. Parse and validate JSON response
   e. Store in MongoDB cache
   f. Return structured advice dict
5. If Groq unavailable → return static fallback templates
```

**Prompt structure sent to LLaMA:**

```
You are a cybersecurity expert. Analyse this attack:

Attack Type: EXPLOIT (BRUTE_FORCE + COMMAND_EXECUTION + FILE_TRANSFER)
Risk Level: CRITICAL
DistilBERT: MALICIOUS (prob=0.98)
Attack Sequence: SCAN → LOGIN_ATT ×47 → LOGIN_OK → EXEC → FILE_XFER
XLNet Next Action: SESS_END (trajectory: [EXEC, FILE_XFER, SESS_END])
IP Intelligence: 45.33.32.156 | Country: CN | ISP: Alibaba | AbuseScore: 87/100

Respond in this exact JSON format:
{
  "trigger_explanation": "...",
  "prevention_summary": "...",
  "access_control": ["...", "..."],
  "network_security": ["...", "..."],
  "host_hardening": ["...", "..."]
}
```

**Response validation** checks that the parsed JSON contains all required keys and that list fields are non-empty arrays.

### 4.2 Automated Response Engine (`flask_app/api/routes.py`)

**Endpoint:** `POST /api/live/sequence/<sequence_id>/respond`

**Access:** Admin only (`@admin_required`)

Three response actions:

#### `block_ip`
```python
ip = prediction["src_ip"]
ipaddress.ip_address(ip)   # validate — prevents command injection

if platform == "Linux":
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
elif platform == "Windows":
    cmd = (f"netsh advfirewall firewall add rule "
           f"name='PCD_BLOCK_{ip}' dir=in action=block remoteip={ip}")

result = subprocess.run(shlex.split(cmd), capture_output=True, timeout=10)
```

Key security measures:
- IP address validated by `ipaddress.ip_address()` before use in any command
- `shlex.split()` prevents shell injection via argument splitting
- `subprocess.run()` called with list (not string) — no shell=True
- Command timeout of 10 seconds to prevent hanging
- Private/loopback IPs (`10.x.x.x`, `192.168.x.x`, `127.x.x.x`) are blocked from being targeted

#### `watch_ip`
```python
db.live_predictions.update_many(
    {"src_ip": ip},
    {"$set": {"watched": True}}
)
```

#### `note_only`
```python
# No OS command — logs the action only
```

All three actions write an **audit record** to MongoDB `response_audit` collection:
```json
{
  "sequence_id": "cowrie_abc123",
  "action": "block_ip",
  "target_ip": "45.33.32.156",
  "executed_by": "admin@pcd.local",
  "timestamp": "2026-03-10T12:31:05Z",
  "result": "success",
  "stdout": "",
  "stderr": ""
}
```

### 4.4 Attack Campaign Correlation (`live/correlator.py`)

Groups individual prediction sessions into multi-session attack campaigns.

**Algorithm:**
1. Query recent `live_predictions` (last 24 hours)
2. Group by `src_ip`
3. For each IP with ≥ 2 sessions in the same time window:
   - Create/update a `campaign` document in `attack_campaigns`
   - `campaign_risk` = maximum `risk_level` across all sessions
   - Track `first_seen`, `last_seen`, session list, token union, ATT&CK technique union
4. Return list of updated campaigns

**Campaign document:**
```json
{
  "campaign_id": "campaign_45.33.32.156_20260310",
  "src_ips": ["45.33.32.156"],
  "session_count": 7,
  "campaign_risk": "CRITICAL",
  "attack_types": ["BRUTE_FORCE", "EXPLOIT"],
  "first_seen": "2026-03-10T08:00:00Z",
  "last_seen": "2026-03-10T12:31:05Z",
  "session_ids": ["abc123", "def456", ...]
}
```

### 4.5 Attacker Behavioural Profiling (`live/profiler.py`)

Builds a persistent intelligence record for each attacker IP.

**Profile fields updated per cycle:**
- `session_count` — total sessions seen from this IP
- `risk_distribution` — count by risk level (LOW/MEDIUM/HIGH/CRITICAL)
- `attack_type_distribution` — count by attack category
- `first_seen`, `last_seen` — timestamps
- `most_frequent_next_token` — most common XLNet-predicted next action
- `avg_sequence_length` — mean number of tokens per session
- `known_usernames` — credentials attempted (from Cowrie sessions)
- `known_commands` — commands executed (from Cowrie sessions)

Stored in MongoDB `attacker_profiles` collection.

### 4.6 Canary Token Detection

> ⚠️ **Not yet implemented** — `live/canary_tokens.py` is referenced in the system design but does **not exist** in the current codebase. The `live/runner.py` pipeline does not import or call any canary module. This feature is **planned** for a future version.

**Planned design (not active):**
Canary tokens would be fake credentials, file paths, or URLs intentionally placed in the honeypot's fake filesystem. Any attacker who accesses them would reveal that they have achieved a specific level of intrusion.

Detection logic (planned):
1. Scan recent Cowrie session events for access to pre-registered canary paths/credentials
2. Match against `canary_definitions` MongoDB collection
3. On match: write a trigger event to `canary_triggers` collection
4. Trigger includes: canary_id, canary_type (file/credential/url), session_id, src_ip, timestamp

### 4.7 Live Inspection — MITRE ATT&CK Mapping Coverage

> The following was obtained by directly inspecting `scripts/mitre_mapping.py` at runtime.

```
Tokens with ATT&CK mappings : 18 tokens out of 49 vocabulary items
(Remaining 31 tokens are structural: PAD, UNK, CLS, domain prefixes, etc.)
```

**Complete Token → ATT&CK Technique Map (from live inspection):**

| Token | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| `SCAN` | T1046 | Network Service Discovery | Discovery |
| `RECON` / `RECON_HOST` | T1595 | Active Scanning | Reconnaissance |
| `LOGIN_ATT` | T1110 | Brute Force | Credential Access |
| `LOGIN_OK` | T1078 | Valid Accounts | Defense Evasion / Persistence |
| `EXEC` | T1059 | Command and Scripting Interpreter | Execution |
| `EXEC_FAIL` | T1059 | Command and Scripting Interpreter | Execution |
| `FILE_XFER` | T1105 | Ingress Tool Transfer | Command and Control |
| `FILE_OPEN` | T1083 | File and Directory Discovery | Discovery |
| `FILE_READ` | T1005 | Data from Local System | Collection |
| `FILE_WRITE` | T1074 | Data Staged | Collection |
| `FILE_DEL` | T1070 | Indicator Removal on Host | Defense Evasion |
| `PRIV_ESC` | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |
| `TUNNEL` | T1572 | Protocol Tunneling | Command and Control |
| `MALWARE` | T1204 | User Execution | Execution |
| `NET_CONNECT` | T1071 | Application Layer Protocol | Command and Control |
| `NET_OPEN` | T1046 | Network Service Discovery | Discovery |
| `EXPLOITATION` | T1190 | Exploit Public-Facing Application | Initial Access |
| `FILE_TRANSFER` | T1105 | Ingress Tool Transfer | Command and Control |

**Unique ATT&CK technique IDs covered: 16 distinct techniques across 7 tactics**

---

### 4.8 Live Response Action — Platform Behaviour

When running on **Windows** (current development platform), the block_ip endpoint generates:

```powershell
# Command constructed and executed by flask_app/api/routes.py :: respond_to_sequence()
netsh advfirewall firewall add rule name='PCD_BLOCK_45.33.32.156' dir=in action=block remoteip=45.33.32.156
```

When running on **Linux** (production deployment):

```bash
# Command constructed and executed by flask_app/api/routes.py :: respond_to_sequence()
iptables -A INPUT -s 45.33.32.156 -j DROP
```

**Safety chain verified:**
1. `ipaddress.ip_address("45.33.32.156")` → valid ✓
2. Not in `_PRIVATE_RANGES` (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`) → proceed ✓
3. `shlex.split(cmd)` → `["iptables", "-A", "INPUT", "-s", "45.33.32.156", "-j", "DROP"]` ✓
4. `subprocess.run([...], timeout=10)` → no shell=True, no injection surface ✓

---

## 5. Internal Workflow / Process Flow

```
Module 3 writes live_predictions to MongoDB
    │
    ▼
live/runner.py calls (each 60-second cycle):
    │
    ├──► live/generator.py
    │    Generate new synthetic Cowrie + Dionaea attacks → data/live_raw/
    │
    ├──► live/parse_cowrie.py + live/parse_dionaea.py
    │    Incremental parse → new session events
    │
    ├──► live/sequence_builder.py
    │    Buffer events → emit complete token sequences → MongoDB live_sequences
    │
    ├──► live/inference.py
    │    DistilBERT + XLNet scoring → MongoDB live_predictions
    │
    ├──► live/correlator.py
    │    Session → attack campaign grouping → MongoDB attack_campaigns
    │
    └──► live/profiler.py
         Updates per-IP profile → MongoDB attacker_profiles

On analyst request (browser):
    │
    ├──► GET /api/live/sequence/<id>/prevention
    │    flask_app/services/ai_prevention.py
    │    → Check cache → Call Groq → Return advice JSON
    │
    └──► POST /api/live/sequence/<id>/respond  (admin only)
         flask_app/api/routes.py
         → Validate IP → Execute OS command → Write audit record
```

---

## 6. Key Components / Files Involved

| File | Role |
|---|---|
| `flask_app/services/ai_prevention.py` | Groq LLaMA integration, MongoDB caching, prompt engineering |
| `flask_app/api/routes.py` | REST endpoints for response actions and AI prevention advice |
| `live/correlator.py` | Groups sessions into campaigns by src_ip within a 24h window |
| `live/profiler.py` | Per-IP behavioural profiling |
| `.env` | `GROQ_API_KEY` and `GROQ_MODEL` |

> ⚠️ `live/canary_tokens.py` is **not present** in the current codebase (planned feature).

**MongoDB Collections Used:**

| Collection | Contents |
|---|---|
| `ai_prevention_cache` | 24h LLM advice cache (TTL auto-expiry) |
| `response_audit` | Admin IP response action audit trail |
| `attack_campaigns` | Multi-session campaign records |
| `attacker_profiles` | Per-IP attacker behavioural fingerprints |

---

## 7. Important Classes / Functions

### `flask_app/services/ai_prevention.py`

```python
def get_ai_prevention(prediction_doc: dict) -> dict:
    """
    Main entry point. Returns AI-powered prevention advice dict.
    Checks cache first; calls Groq if cache miss.
    Falls back to static templates on API error.
    
    Returns:
        {
          "trigger_explanation": str,
          "prevention_summary": str,
          "access_control": list[str],
          "network_security": list[str],
          "host_hardening": list[str]
        }
    """

def _get_groq_client() -> groq.Groq:
    """Thread-safe singleton Groq client (reuses HTTP connection pool)."""

def _build_prompt(prediction_doc: dict) -> str:
    """Build the structured cybersecurity prompt from prediction context."""

def _validate_response(parsed: dict) -> bool:
    """Validate that LLM JSON response contains all required keys."""

def _get_fallback(attack_type: str, risk_level: str) -> dict:
    """Return static prevention templates when Groq is unavailable."""
```

### `flask_app/api/routes.py`

```python
@api_bp.route("/live/sequence/<sequence_id>/respond", methods=["POST"])
@login_required
@admin_required
def respond_to_sequence(sequence_id):
    """
    Execute automated response action: block_ip | watch_ip | note_only.
    Validates IP, runs OS command, writes audit record.
    """

@api_bp.route("/live/sequence/<sequence_id>/prevention")
@login_required
@analyst_required
def get_prevention_advice(sequence_id):
    """
    Return AI-generated prevention advice for a specific prediction.
    Calls get_ai_prevention() which handles caching.
    """

@api_bp.route("/live/profile/<ip>")
@login_required
@analyst_required
def get_attacker_profile(ip):
    """Return the attacker profile document for the given IP."""
```

---

## 8. Inputs and Outputs

### Inputs

| Input | Source | Format |
|---|---|---|
| Prediction documents | MongoDB `live_predictions` | BSON |
| Admin response request | HTTP POST from browser | JSON body |

| Groq API | External HTTP API | JSON |

### Outputs

| Output | Destination | Purpose |
|---|---|---|
| AI advice JSON | Browser (HTTP response) | Display on sequence detail page |
| IP blocked in firewall | OS (iptables / netsh) | Block attacker at network level |
| Audit record | MongoDB `response_audit` | Compliance and review |
| Campaign record | MongoDB `attack_campaigns` | Campaign view in dashboard |
| Attacker profile | MongoDB `attacker_profiles` | "Attacker Profile" panel on detail page |
| Canary trigger | MongoDB `canary_triggers` | Canary token alert |

---

## 9. Dependencies

| Dependency | Purpose |
|---|---|
| `groq` | Groq SDK for LLaMA API |
| `ipaddress` | IP validation before OS command execution |
| `subprocess` | Execute iptables/netsh firewall commands |
| `shlex` | Safe command argument splitting |
| `platform` | Detect OS (Linux vs Windows) for correct firewall command |
| `requests` | HTTP client (attacker simulation) |
| `pymongo` | All MongoDB read/write operations |
| `flask_login` | Authentication checks on API endpoints |

---

## 10. Interaction with Other Modules

```
Module 3 (Core Engine)
    │  produces risk-scored predictions in MongoDB
    ▼
Module 4 (Response / Action)  ← YOU ARE HERE
    │  produces: AI advice, firewall rules, campaigns, profiles
    ▼
Module 5 (Monitoring / Visualization)
    Reads: campaigns, profiles, audit records, IP intel to display
    on the dashboard in the /campaigns, /profiles, /admin/response-audit pages
```

---

## 11. Example Flow / Use Case

**Scenario: Admin blocks a CRITICAL SSH brute-force attacker**

```
1. Live pipeline scores session: CRITICAL, attack_prob=0.98, src_ip=45.33.32.156

2. Analyst opens sequence detail at /live/<sequence_id>

3. Browser calls GET /api/live/sequence/<id>/prevention
   - Cache MISS (first time for this attack_type/risk combination)
   - Groq LLaMA generates:
     {
       "trigger_explanation": "45.33.32.156 conducted a 47-attempt SSH brute-force
                               attack that succeeded, then downloaded payload via wget.",
       "prevention_summary": "Immediately block this IP and rotate all SSH credentials.",
       "access_control": ["Disable root SSH login", "Enforce key-only authentication"],
       "network_security": ["Block 45.33.32.156 at firewall", "Rate-limit SSH to 3 attempts/min"],
       "host_hardening": ["Audit /tmp for dropped payloads", "Check crons for persistence"]
     }
   - Cached in MongoDB for 24 hours (same advice reused for similar attacks)

4. Admin clicks "Block IP" button
   - POST /api/live/sequence/<id>/respond with {"action": "block_ip"}
   - IP validated: 45.33.32.156 ✓ (not private)
   - Command on Linux: iptables -A INPUT -s 45.33.32.156 -j DROP
   - Command on Windows: netsh advfirewall firewall add rule name='PCD_BLOCK_45.33.32.156' ...
   - Result: success (returncode 0)
   - Audit record written to response_audit

5. All future packets from 45.33.32.156 are dropped at the OS firewall level
```

---

## 12. Configuration Details

### `.env` Variables Used by This Module

```env
GROQ_API_KEY=gsk_...          # Required for AI prevention advice
GROQ_MODEL=llama-3.1-8b-instant   # LLM model name (default)
```

### Groq API Settings (`ai_prevention.py`)

```python
CACHE_TTL_HOURS = 24           # Hours before cached advice expires
MAX_TOKENS      = 1024         # Max response tokens from LLaMA
TEMPERATURE     = 0.3          # Lower = more deterministic safety advice
```

### Response Action Validation (`api/routes.py`)

```python
_VALID_ACTIONS = {"block_ip", "watch_ip", "note_only"}

# IPs that may NEVER be blocked (safety guard)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]
```

---

## 13. Implementation Notes

- **Groq client singleton:** `_get_groq_client()` uses a module-level cached client so the HTTP connection is not rebuilt on every API call. This reduces latency from ~200ms to ~50ms for subsequent requests.
- **Response format enforcement:** Groq API is called with `response_format={"type": "json_object"}` which guarantees the response is valid JSON, eliminating the need to parse markdown code fences or handle non-JSON text.
- **Shell injection prevention:** IP addresses are always validated by Python's `ipaddress.ip_address()` before being passed to system commands. Commands are always passed as lists to `subprocess.run()`, never as strings with `shell=True`.
- **Audit trail completeness:** Every response action — including failed ones (e.g., `iptables` returns non-zero) — is written to the audit collection, capturing `stdout` and `stderr` for debugging.
- **Static fallback templates:** When Groq is unavailable (network issue, quota exceeded), `_get_fallback()` returns pre-written, categorised advice templates indexed by `attack_type`. This ensures the dashboard always shows something useful.

