# Proactive Cyber Deception (PCD)

**An AI-powered honeypot monitoring and real-time attack intelligence platform.**

> Captures real attacker behaviour in honeypots → classifies it with transformer ML models →
> predicts the attacker's next action → recommends countermeasures → all through a live web dashboard.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Architecture](#architecture)
3. [Module Breakdown](#module-breakdown)
4. [Tech Stack](#tech-stack)
5. [Setup & Installation](#setup--installation)
6. [Running the Project](#running-the-project)
7. [Role-Based Access Control](#role-based-access-control)
8. [Key Workflows](#key-workflows)
9. [Folder Structure](#folder-structure)
10. [MongoDB Collections](#mongodb-collections)

---

## What It Does

Traditional intrusion detection alerts **after** an attack. PCD takes a
**deception-first, proactive** stance:

| Problem | PCD Solution |
|---|---|
| Signature-based IDS misses unknown attacks | ML models learn *behavioural sequences*, not signatures |
| Slow incident response | Real-time XLNet prediction shows attacker's *next* move |
| Manual, inconsistent response | One-click: block IP, watchlist, or log-only |
| Threat data hard to share | Export as CSV or STIX 2.1 bundle for SIEM integration |
| Analysts lack context | Groq LLaMA generates specific, attack-context-aware advice |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  HONEYPOTS (Docker)                                      │
│  Cowrie (SSH/Telnet)    Dionaea (HTTP/FTP/SMB/MySQL)     │
│       │                        │                         │
│       └──────── raw logs ──────┘                         │
│                    │                                     │
│                    ▼                                     │
│  LIVE PIPELINE  (live/runner.py  — 60s cycles)           │
│  ┌─────────────────────────────────────────────────┐     │
│  │ generator  → parse_cowrie / parse_dionaea        │     │
│  │ sequence_builder → inference (BERT + XLNet)      │     │
│  │ correlator → attack_campaigns                    │     │
│  │ canary_tokens + profiler                         │     │
│  │                  │                               │     │
│  │           MongoDB Collections                    │     │
│  └─────────────────────────────────────────────────┘     │
│                    │                                     │
│                    ▼                                     │
│  FLASK DASHBOARD  (flask_app/)                           │
│  Browser ←  HTTP REST + WebSocket  → Flask + SocketIO   │
└──────────────────────────────────────────────────────────┘

OFFLINE PIPELINE (one-time training — scripts/)
  parse_* → build_sequences → train_distilbert / train_xlnet
  → evaluate_* → severity_scorer → reports/
```

---

## Module Breakdown

### Module 1 — Data Collection

**Captures** raw attacker behaviour from honeypots.

| Component | Role |
|---|---|
| `docker/docker-compose.yml` | Launches Cowrie, Dionaea, MongoDB containers |
| `live/generator.py` | **Dynamically generates** new synthetic attack events each cycle (random IPs, credentials, commands) |
| `scripts/_traffic.py` | Synthetic attack traffic generator using real network sockets (testing/red-team) |
| `data/raw/` | Archived raw Cowrie JSON + Dionaea text logs (offline training baseline) |

### Module 2 — Processing & Analysis

**Transforms** raw logs into normalised token sequences for ML input.

| Component | Role |
|---|---|
| `scripts/token_definitions.py` | **Master vocabulary** — single source of truth for all tokens |
| `scripts/parse_cowrie.py` / `live/parse_cowrie.py` | Batch + incremental Cowrie parsers |
| `scripts/parse_dionaea.py` / `live/parse_dionaea.py` | Batch + incremental Dionaea parsers |
| `scripts/process_beth.py` | BETH dataset CSV processor (sliding-window chunking) |
| `scripts/build_sequences.py` | Train/val/test dataset builder with stratified splits |
| `live/sequence_builder.py` | Buffers live events → emits complete sequences |

**Example token sequence:**
```
cowrie.session.connect    →  SCAN
cowrie.login.failed ×47   →  LOGIN_ATT (×47)
cowrie.login.success      →  LOGIN_OK
cowrie.command.input      →  EXEC
cowrie.session.file_download → FILE_XFER
cowrie.session.closed     →  SESS_END

Final: [COWRIE] SCAN LOGIN_ATT LOGIN_OK EXEC FILE_XFER SESS_END
```

### Module 3 — Core Detection Engine

**Scores** every session with two complementary ML models.

**DistilBERT Attack Classifier**
- Binary classification: MALICIOUS / BENIGN
- Output: `attack_prob` (0.0–1.0)
- Fine-tuned on token sequences from Cowrie, Dionaea, and BETH datasets

**XLNet Behaviour Predictor**
- Language model trained on attack token sequences
- Output: `predicted_next_token` + `perplexity` → `anomaly_score`

**Combined Severity Score:**
```
token_sev_scaled = (mean_token_severity − 1.0) / 3.0
combined = token_sev_scaled × 0.25
         + attack_prob      × 1.50
         + anomaly_score    × 1.25

Thresholds:  < 0.5 → LOW   |  < 1.2 → MEDIUM
             < 2.0 → HIGH  |  ≥ 2.0 → CRITICAL
```

**MITRE ATT&CK Mapping:** Every token is looked up in `scripts/mitre_mapping.py` and mapped to technique IDs (T1046, T1110, T1059, etc.).

### Module 4 — Response & Action

**Reacts** to detected threats through advice, firewall actions, and profiling.

| Sub-feature | Component |
|---|---|
| AI Prevention Advice | `flask_app/services/ai_prevention.py` — Groq LLaMA, 24h MongoDB cache |
| Automated Firewall Block | `flask_app/api/routes.py` → `respond_to_sequence()` |
| Attack Campaign Correlation | `live/correlator.py` — groups sessions by src_ip within 24h window |
| Attacker Behavioural Profiling | `live/profiler.py` — per-IP profile in MongoDB |
| Canary Token Detection | ⚠️ **Planned** — `live/canary_tokens.py` does not yet exist in the codebase |

**Automated response actions** (admin only):
- `block_ip` → `iptables -A INPUT -s <ip> -j DROP` (Linux) or `netsh advfirewall` (Windows)
- `watch_ip` → sets `watched: True` flag on all predictions from that IP
- `note_only` → audit log entry only

### Module 5 — Dashboard & Visualisation

**Displays** everything through a role-aware Flask web application.

| Page | Access | Description |
|---|---|---|
| `/` | Public | Landing page |
| `/dashboard` | All users | Summary cards: sessions, risk counts, honeypot status |
| `/live` | All users | Real-time prediction table (WebSocket, 12s updates) |
| `/live/<id>` | Analyst+ | Sequence detail: token flow, AI advice, MITRE map, escalation graph |
| `/live/campaigns` | Analyst+ | Attack campaign list |
| `/honeypots` | All users | Honeypot session statistics |
| `/models` | All users | Offline ML evaluation metrics |
| `/reports` | All users | Severity distribution and model agreement |
| `/admin/settings` | Admin | User management |
| `/admin/response-audit` | Admin | Automated response action log |

---

## Tech Stack

| Category | Technology |
|---|---|
| Web | Flask 3.x, Flask-Login, Flask-SocketIO, Flask-CORS |
| Database | MongoDB 7 (PyMongo) |
| ML / AI | PyTorch 2.x, Hugging Face Transformers (DistilBERT + XLNet) |
| LLM Advice | Groq API (LLaMA-3.1-8b-instant) |
| Auth | bcrypt, Flask-Login sessions |
| Data | NumPy, Pandas, scikit-learn |
| Infra | Docker Compose (Cowrie + Dionaea + MongoDB) |
| Export | CSV, STIX 2.1 JSON |

---

## Setup & Installation

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ (3.11 recommended) |
| Docker Desktop | Latest stable |
| MongoDB | 7 (via Docker) |

### 1. Clone and create virtual environment

```bash
git clone <repo-url>
cd proactive-cyber-deception

# Windows
python -m venv .venv && .venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv && source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> ⚠️ `torch` is ~2 GB. Ensure a stable internet connection.

### 3. Configure environment variables

Create `.env` in the project root:

```env
SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
MONGO_URI=mongodb://localhost:27017/
GROQ_API_KEY=<from https://console.groq.com/>
```

### 4. Start MongoDB

```bash
docker compose -f docker/docker-compose.yml up mongodb -d
```

### 5. Create your first user

Start the dashboard (see below), then navigate to **http://localhost:5000/signup**.

To promote a user to admin:

```bash
docker exec -it mongodb mongosh
use proactive_deception
db.users.updateOne({ username: "yourname" }, { $set: { role: "admin" } })
```

---

## Running the Project

### Full stack (recommended — two terminals)

**Terminal 1 — Dashboard:**
```bash
python run_flask.py
# → http://localhost:5000
```

**Terminal 2 — Live inference pipeline:**
```bash
python -m live.runner
```

### Test mode (no Docker required)

Runs the full pipeline for one cycle then exits:
```bash
python -m live.runner --dry-run
```

### Offline training pipeline (first time only)

```bash
# 1. Parse raw logs
python scripts/parse_cowrie.py
python scripts/parse_dionaea.py
python scripts/process_beth.py    # requires BETH CSVs in data/beth/raw/

# 2. Build datasets
python scripts/build_sequences.py

# 3. Train models
python scripts/train_distilbert.py
python scripts/train_xlnet.py

# 4. Generate evaluation reports
python scripts/evaluate_distilbert.py
python scripts/evaluate_xlnet.py
python scripts/severity_scorer.py
```

---

## Role-Based Access Control

| Role | Capabilities |
|---|---|
| `student` | Read-only access; source IPs are hidden |
| `analyst` | Full investigation: sequence detail, campaign view, AI advice, export |
| `admin` | Everything + automated response (block/watch), user management |

Roles are enforced via `flask_app/decorators.py` — the single source of truth for RBAC, used uniformly across `auth/`, `main/`, `api/`, and `admin/` blueprints.

---

## Key Workflows

### Live pipeline cycle (every 60 seconds)

```
1. generator.py     → generate new synthetic Cowrie + Dionaea attack events
2. parse_cowrie     → parse new Cowrie log lines (incremental)
3. parse_dionaea    → parse new Dionaea log lines (incremental)
4. sequence_builder → buffer events → emit complete token sequences
5. inference.py     → DistilBERT classification + XLNet next-step prediction
                      → combined severity score → risk level
                      → MITRE ATT&CK mapping → write to live_predictions
6. [correlator]     → emit campaign updates
7. [profiler]       → update attacker fingerprints
8. sleep(interval)
```

### Analyst investigation workflow

1. Log in as **analyst** or **admin**
2. Open **Live Monitor** (`/live`) — predictions appear every 12 s
3. Click a **HIGH** or **CRITICAL** row → Sequence Detail page
4. Review: token flow, escalation graph, DistilBERT/XLNet scores
5. Read **AI Prevention Advice** (Groq LLaMA) — immediate/short/long-term actions
6. Update alert **status** (`investigating` → `mitigated` → `closed`)
7. Add **analyst note** for team record
8. *[Admin]* Click **Block IP** / **Watch IP** / **Note Only**
9. Export **CSV** or **STIX 2.1** for SIEM

---

## Folder Structure

```
proactive-cyber-deception/
├── .env                      # Secrets (never commit)
├── requirements.txt          # Python dependencies
├── shared_db.py              # Thread-safe MongoDB singleton
├── run_flask.py              # Application entry point
│
├── docker/
│   └── docker-compose.yml   # Cowrie + Dionaea + MongoDB
│
├── flask_app/                # Web dashboard
│   ├── __init__.py           # create_app() factory
│   ├── config.py             # Config class (reads .env)
│   ├── models.py             # User model (bcrypt, MongoDB)
│   ├── decorators.py         # ★ Centralised RBAC decorators
│   ├── utils.py              # ★ Shared utilities (prevention_summary)
│   ├── ai_prevention.py      # Groq LLaMA advice + MongoDB cache
│   ├── auth/routes.py        # Login, signup, logout
│   ├── main/routes.py        # Page rendering
│   ├── admin/routes.py       # Admin settings
│   ├── api/routes.py         # All JSON REST endpoints
│   ├── ws/events.py          # WebSocket live feed (12s push)
│   ├── static/               # CSS, JS, images
│   └── templates/            # Jinja2 HTML templates
│
├── scripts/                  # Offline processing & training
│   ├── token_definitions.py  # ★ Master token vocabulary
│   ├── parse_cowrie.py       # Batch Cowrie log parser
│   ├── parse_dionaea.py      # Batch Dionaea log parser
│   ├── process_beth.py       # BETH CSV processor
│   ├── build_sequences.py    # Train/val/test dataset builder
│   ├── train_distilbert.py   # DistilBERT fine-tuning
│   ├── train_xlnet.py        # XLNet fine-tuning
│   ├── evaluate_distilbert.py
│   ├── evaluate_xlnet.py
│   ├── severity_scorer.py    # Combined severity scoring
│   ├── mitre_mapping.py      # MITRE ATT&CK lookup table
│   └── _traffic.py           # Red-team traffic simulator
│
├── live/                     # Live inference pipeline
│   ├── runner.py             # ★ Main 60-second loop (7 stages)
│   ├── generator.py          # Synthetic attack event generator (random IPs/creds/commands)
│   ├── parse_cowrie.py       # Incremental Cowrie parser (offset-tracked)
│   ├── parse_dionaea.py      # Incremental Dionaea parser (offset-tracked)
│   ├── sequence_builder.py   # Event buffer → sequence emitter
│   ├── inference.py          # DistilBERT + XLNet scoring
│   ├── correlator.py         # Session → Campaign grouping
│   └── profiler.py           # Per-IP attacker profiling
│   # Note: canary_tokens.py is planned but not yet implemented
│
├── models/
│   ├── distilbert_attack_classifier/
│   └── xlnet_behaviour_predictor/
│
├── data/
│   ├── raw/cowrie/           # Cowrie JSON logs (offline training baseline)
│   ├── raw/dionaea/          # Dionaea text logs (offline training baseline)
│   ├── beth/raw/             # BETH dataset CSVs
│   ├── processed/            # Parsed events + dataset splits
│   ├── live_raw/cowrie/      # Dated synthetic Cowrie JSON events (generator output)
│   └── live_raw/dionaea/     # Dated synthetic Dionaea JSON events (generator output)
│
└── reports/                  # JSON evaluation reports
    ├── distilbert_evaluation.json
    ├── xlnet_evaluation.json
    └── severity_report.json
```

---

## MongoDB Collections

### ✅ Complete Inventory (10 collections)

All collections are actively used and properly indexed. No redundant collections exist.

| Collection | Purpose | Status | Example Fields |
|---|---|---|---|
| **`live_predictions`** | Core ML predictions for each scored session | ESSENTIAL | `sequence_id`, `risk_level`, `attack_prob`, `predicted_next_token`, `inferred_at` |
| **`live_events`** | Raw parsed events from Cowrie and Dionaea honeypots | ESSENTIAL | `session_id`, `eventtype`, `timestamp`, `src_ip`, `username` |
| **`live_sequences`** | Built token sequences ready for inference | ESSENTIAL | `sequence_id`, `tokens[]`, `date`, `session_id` |
| **`attack_campaigns`** | Correlated attack campaigns grouped by IP/HASSH/username | ESSENTIAL | `campaign_id`, `sequence_ids[]`, `src_ips[]`, `campaign_risk`, `session_count` |
| **`attacker_profiles`** | Per-IP behavioral fingerprint (session count, attack types, risk levels) | ESSENTIAL | `src_ip`, `session_count`, `attack_type_counts{}`, `peak_risk`, `repeat_attacker`, `token_signature[]` |
| **`ai_prevention_cache`** | 24-hour TTL cache for Groq LLaMA prevention advice | ESSENTIAL | `cache_key`, `prevention{}`, `cached_at` |
| **`sequence_notes`** | Analyst annotations and case notes on sequences | USEFUL | `sequence_id`, `author`, `content`, `created_at`, `updated_at` |
| **`canary_triggers`** | Deception token (fake credential/file) access alerts | USEFUL | `session_id`, `token_name`, `token_type`, `logged_at`, `src_ip` |
| **`response_audit`** | Audit trail of admin-triggered response actions (block_ip, watch_ip, note_only) | USEFUL | `action`, `sequence_id`, `src_ip`, `performed_by`, `performed_at`, `reason` |
| **`users`** | User accounts with Flask authentication (student/analyst/admin roles) | ESSENTIAL | `username`, `password_hash`, `role`, `is_active`, `created_at` |

### 📊 Indexing Strategy

All collections have optimized indexes (created once via `scripts/setup_indexes.py`):

```
✅ live_predictions       — 7 indexes      (sequence_id, inferred_at, date, risk_level, src_ip, source, compound indexes)
✅ attack_campaigns       — 4 indexes      (campaign_id unique, date, src_ips, campaign_risk)
✅ attacker_profiles      — 2 indexes      (src_ip unique, session_count)
✅ ai_prevention_cache    — 2 indexes      (cache_key unique, cached_at with 24h TTL auto-expire)
✅ sequence_notes         — 2 indexes      (sequence_id, created_at)
✅ canary_triggers        — 2 indexes      (session_id, logged_at)
✅ response_audit         — 2 indexes      (performed_at, sequence_id)
✅ users                  — 1 index        (username unique)
```

### 🔧 TTL Configuration

The `ai_prevention_cache` uses MongoDB's automatic expiration feature:
- **TTL Index:** `cached_at` with 86,400 seconds (24 hours)
- **Effect:** Old cache entries are automatically deleted by MongoDB without manual cleanup
- **Purpose:** Prevents unbounded growth while keeping recent Groq LLaMA advice readily available

### ✅ Collection Health Status

- **Total collections:** 10
- **With unique indexes:** 3 (sequence_id, campaign_id, src_ip, username, cache_key)
- **With TTL:** 1 (ai_prevention_cache)
- **Redundant collections:** 0 ❌ NONE — all are distinct in purpose
- **Unused collections:** 0 ❌ NONE — all are actively queried

---

*Generated: 2026-03-14 | Updated: 2026-04-15 | Proactive Cyber Deception v1.0*

*Validated model performance — DistilBERT: 95.63% accuracy, F1=0.9537 | XLNet: top-5 98.82%, anomaly recall 98.44% — from `reports/distilbert_evaluation.json` and `reports/xlnet_evaluation.json`*
