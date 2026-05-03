# Module 5 — Monitoring and Visualization Module

---

## 1. Module Name

**Monitoring and Visualization Module (Web Dashboard)**

---

## 2. Module Purpose

This module is the **user-facing interface** of the entire system. It provides security teams with:

- A **real-time live monitor** that updates automatically via WebSocket (no page refresh)
- **Role-based access control** so students, analysts, and admins each see an appropriate level of detail
- **Drill-down sequence analysis** pages showing token flow, escalation charts, AI advice, and MITRE techniques
- **Offline ML performance reports** (DistilBERT evaluation, XLNet evaluation, severity distribution)
- **Export capabilities** for CSV and STIX 2.1 threat-sharing format
- **Admin panel** for user management and audit trail review

---

## 3. Problem the Module Solves

Even the best detection engine is useless if results are buried in log files or JSON reports. Security teams need:

- **Immediacy** — real-time push notifications of new detections without manual refresh
- **Context** — understanding *why* a session was classified as CRITICAL, not just that it was
- **Appropriately scoped access** — interns should not see attacker IPs; analysts should not have block-IP power
- **Interoperability** — threat intelligence must be exportable to SOC/SIEM in standard formats

This module solves each:
- WebSocket push delivers predictions within 12 seconds of scoring
- Sequence detail page shows every token, its severity, MITRE technique, escalation chart, and LLM advice
- Three-role RBAC (student / analyst / admin) enforced at every route and data endpoint
- CSV and STIX 2.1 export built into the analyst toolbar

---

## 4. Detailed Explanation of How It Works

### 4.1 Application Factory (`flask_app/__init__.py`)

```python
def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*",
                      async_mode="threading")

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp,   url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    from flask_app.ws import events  # register WebSocket handlers as side-effect
    return app
```

### 4.2 Role-Based Access Control (`flask_app/services/decorators.py`)

Four decorators protect every route consistently:

```python
# Used on page routes (redirects to login on failure)
@analyst_required      # requires role: analyst OR admin
@admin_required        # requires role: admin only

# Used on API routes (returns JSON 403 on failure)
@api_analyst_required
@api_admin_required
```

> **Note:** All four decorators are defined in `flask_app/services/decorators.py` and imported into both `main/routes.py` and `api/routes.py`.

Applied via three roles stored in MongoDB `users.role`:
- `student` — read-only; source IPs are redacted (shown as `*.*.*.*`)
- `analyst` — full read access; can annotate, export, view campaigns, profiles
- `admin` — all analyst capabilities + user management + IP block responses

### 4.3 Authentication (`flask_app/auth/routes.py`)

| Route | Method | Description |
|---|---|---|
| `/` | GET | Public landing page |
| `/login` | GET/POST | Username + password login via Flask-Login |
| `/signup` | GET/POST | New user registration (analyst or student role) |
| `/logout` | GET | Clear session |

Security measures:
- Passwords hashed by bcrypt (cost factor 12)
- Open-redirect prevention on the `next` parameter (validated against current host via `urlparse`)
- Signup prevents self-elevation to admin role

### 4.4 Page Routes (`flask_app/main/routes.py`)

All page routes are thin renderers — business logic stays in `api/routes.py`.

| Route | Method | Access | Template |
|---|---|---|---|
| `/dashboard` | GET | All users (login required) | `dashboard/index.html` |
| `/live` | GET | All users (login required) | `live/monitor.html` |
| `/live/<sequence_id>` | GET | Analyst+ | `live/sequence_detail.html` |
| `/live/campaigns` | GET | Analyst+ | `live/campaigns.html` |
| `/live/campaigns/<id>` | GET | Analyst+ | `live/campaign_detail.html` |
| `/honeypots` | GET | All users (login required) | `honeypots/index.html` |
| `/models` | GET | All users (login required) | `models/index.html` |
| `/reports` | GET | All users (login required) | `reports/index.html` |
| `/explainability` | GET | All users (login required) | `explainability/index.html` |
| `/admin/response-audit` | GET | Admin only | `admin/response_audit.html` |

### 4.5 WebSocket Live Feed (`flask_app/ws/events.py`)

The WebSocket system delivers real-time prediction updates to all connected browsers.

**Namespace:** `/ws/live`

**Background polling thread:**
```python
def _background_feed():
    """
    Runs as a daemon thread (one instance per process, singleton-guarded).
    Every 12 seconds:
      1. Queries MongoDB live_predictions for records with
         inferred_at > last_seen_time
      2. Redacts src_ip for student users
      3. Emits 'new_predictions' event to all clients on /ws/live
      4. Updates last_seen_time
    """
```

**Thread lifecycle:**
- Thread started once (on first client connect) and never restarted
- Double-checked locking prevents duplicate threads on rapid reconnections
- Thread is a daemon — dies automatically when Flask process exits

**WebSocket events handled:**

| Event | Direction | Handler |
|---|---|---|
| `connect` | Client → Server | Start background thread if not running; log connection |
| `subscribe` | Client → Server | Client confirms which namespace it wants |
| `new_predictions` | Server → Client | Emits array of new prediction objects |
| `disconnect` | Client → Server | Log disconnection |

### 4.6 JSON REST API (`flask_app/api/routes.py`)

All data consumed by the browser JavaScript comes from this blueprint.

**Feature 1 — Live Data Endpoints:**

| Endpoint | Returns |
|---|---|
| `GET /api/live/feed` | Paginated list of predictions with filters |
| `GET /api/live/sequence/<id>` | Full prediction document |
| `GET /api/live/sequence/<id>/prevention` | AI prevention advice |
| `GET /api/live/trends` | Risk count over time (for trend chart) |
| `GET /api/live/campaigns` | All attack campaigns |
| `GET /api/live/profile/<ip>` | Attacker profile |
| `GET /api/live/profiles/top` | Top attacker profiles by session count |

**Feature 2 — Offline Report Endpoints:**

| Endpoint | Returns |
|---|---|
| `GET /api/reports/distilbert` | DistilBERT evaluation JSON |
| `GET /api/reports/xlnet` | XLNet evaluation JSON |
| `GET /api/reports/severity` | Severity distribution report |

**Feature 3 — Admin Endpoints:**

| Endpoint | Returns |
|---|---|
| `GET /api/admin/users` | All user accounts |
| `PATCH /api/admin/users/<id>` | Update user role/active status |
| `DELETE /api/admin/users/<id>` | Delete user account |

**Feature 4 — Export Endpoints:**

| Endpoint | Returns |
|---|---|
| `GET /api/live/export/csv` | CSV of today's predictions (all columns) |
| `GET /api/live/export/stix` | STIX 2.1 bundle (HIGH + CRITICAL only) |

**STIX 2.1 bundle structure:**
```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {
      "type": "threat-actor",
      "id": "threat-actor--<uuid>",
      "name": "Attacker 45.33.32.156",
      "threat_actor_types": ["criminal"],
      "sophistication": "intermediate"
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--<uuid>",
      "name": "T1110 / Brute Force",
      "external_references": [{"url": "https://attack.mitre.org/techniques/T1110/"}]
    },
    {
      "type": "observed-data",
      "id": "observed-data--<uuid>",
      "first_observed": "2026-03-10T12:31:05Z",
      "last_observed":  "2026-03-10T12:31:05Z",
      "number_observed": 1
    }
  ]
}
```

### 4.7 Report Cache (`_report_cache` in `api/routes.py`)

The three large JSON files in `reports/` are loaded into a module-level dictionary on first access:
```python
_report_cache: dict = {}

def _load_report(name: str) -> dict:
    if name not in _report_cache:
        path = Path(current_app.config["REPORTS_DIR"]) / name
        with open(path) as f:
            _report_cache[name] = json.load(f)
    return _report_cache[name]
```

This means the 7 MB `distilbert_evaluation.json` is parsed from disk exactly once per process lifetime — subsequent API calls return in < 1ms.

### 4.8 Live Inspection — Templates, Static Assets & Report Files

> The following was obtained by inspecting the actual `flask_app/` directory structure.

#### Jinja2 Templates (`flask_app/templates/`)

Templates are organised in **subdirectories by feature** (not flat):

| Template File | Page | Access Level |
|---|---|---|
| `public/landing.html` | Landing / welcome page | Public |
| `auth/login.html` | Login form | Public |
| `auth/signup.html` | Registration form | Public |
| `dashboard/index.html` | Main summary dashboard | Login required |
| `live/monitor.html` | Real-time live prediction feed | Login required |
| `live/sequence_detail.html` | Individual sequence drilldown | Analyst+ |
| `live/campaigns.html` | Attack campaign list | Analyst+ |
| `live/campaign_detail.html` | Single campaign view | Analyst+ |
| `honeypots/index.html` | Honeypot status page | Login required |
| `models/index.html` | ML model overview page | Login required |
| `reports/index.html` | Offline evaluation report viewer | Login required |
| `explainability/index.html` | Token-level explainability | Login required |
| `admin/settings.html` | Admin user management | Admin only |
| `admin/response_audit.html` | Admin response audit trail | Admin only |
| `base.html` | Base layout template (navbar, footer) | (inherited) |
| `base_public.html` | Public-page base layout (no auth navbar) | (inherited) |

#### Static Assets (`flask_app/static/`)

| Asset | Size | Purpose |
|---|---|---|
| `css/main.css` | ~59 KB | All custom styles (dark theme, glassmorphism) |
| `js/live_monitor.js` | ~12 KB | WebSocket client, prediction table updates |
| `js/sequence_detail.js` | ~30 KB | Token visualiser, escalation chart renderer |
| `js/dashboard.js` | ~6 KB | Summary chart and stat card updates |
| `js/reports.js` | ~11 KB | Evaluation metric chart rendering |
| `js/campaigns.js` | ~8 KB | Campaign list and detail rendering |
| `js/admin.js` | ~3 KB | Admin user management UI |

#### Report Files (`reports/`)

| File | Size | Contents | When Generated |
|---|---|---|---|
| `distilbert_evaluation.json` | **~7 MB** | 13,141 per-sequence results + aggregate metrics | `python scripts/evaluate_distilbert.py` |
| `xlnet_evaluation.json` | **~4 MB** | 13,141 perplexity scores, next-step predictions | `python scripts/evaluate_xlnet.py` |
| `severity_report.json` | **~5 MB** | Combined severity scores for all test sequences | `python scripts/severity_scorer.py` |

**Total report data: ~16 MB** — loaded into `_report_cache` on first API call, returned in <1ms on subsequent requests.

#### Flask Application Startup Output

Running `python run_flask.py`:

```
 * Serving Flask app 'flask_app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
 * Running on http://0.0.0.0:5000
Press CTRL+C to quit
 * Restarting with watchdog (windowsapi)
 * Debugger is active!
 * Debugger PIN: xxx-xxx-xxx
```

**Available routes registered at startup:**

```
/                        GET     → auth.landing (public)
/login                   GET,POST → auth.login
/signup                  GET,POST → auth.signup
/logout                  GET     → auth.logout
/dashboard               GET     → main.dashboard
/live                    GET     → main.live_monitor
/live/<sequence_id>      GET     → main.sequence_detail
/live/campaigns          GET     → main.campaigns
/live/campaigns/<id>     GET     → main.campaign_detail
/honeypots               GET     → main.honeypots
/models                  GET     → main.models_page
/reports                 GET     → main.reports
/explainability          GET     → main.explainability
/admin/settings          GET     → admin.settings
/admin/response-audit    GET     → main.response_audit  (admin only)
/api/live/summary        GET     → api.live_summary
/api/live/feed           GET     → api.live_feed
/api/live/sequence/<id>  GET     → api.get_sequence
/api/live/sequence/<id>/prevention  GET  → api.get_prevention_advice
/api/live/sequence/<id>/respond     POST → api.respond_to_sequence
/api/live/trends         GET     → api.live_trends
/api/live/campaigns      GET     → api.get_campaigns
/api/live/campaigns/<id> GET     → api.get_campaign
/api/live/ip-intel/<ip>  GET     → api.get_ip_intel
/api/live/profiles/top   GET     → api.get_top_profiles
/api/live/export/csv     GET     → api.export_csv
/api/live/export/stix    GET     → api.export_stix
/api/reports/distilbert  GET     → api.get_distilbert_report
/api/reports/xlnet       GET     → api.get_xlnet_report
/api/reports/severity    GET     → api.get_severity_report
/api/admin/users         GET     → api.get_users
/api/admin/users/<id>    PATCH   → api.update_user
/api/admin/users/<id>    DELETE  → api.delete_user
/ws/live                 WS      → ws.events (namespace)
```

**Total: 31 HTTP endpoints + 1 WebSocket namespace**

---

## 5. Internal Workflow / Process Flow

```
Browser loads /live page
    │
    ├──► HTTP GET /live (main_bp)
    │    Flask renders live.html template
    │
    └──► WebSocket connect to /ws/live
         │
         ▼ ws/events.py
         Background thread starts (if not already running)
         │
         Every 12 seconds:
         │
         ├──► MongoDB query: latest live_predictions
         │
         └──► socketio.emit("new_predictions", data)
                  │
                  ▼ browser JavaScript
                  Update prediction table rows (no page reload)

Analyst clicks prediction row:
    │
    ├──► HTTP GET /live/<sequence_id>
    │    Renders sequence_detail.html
    │
    ├──► Browser JS: GET /api/live/sequence/<id>
    │    Returns full prediction document
    │
    ├──► Browser JS: GET /api/live/sequence/<id>/prevention
    │    Returns AI advice (or cache hit)
    │
    └──► Browser renders:
         - Token flow visualization
         - Escalation chart
         - AI advice panel
         - MITRE ATT&CK technique list
         - IP intelligence panel
         - Analyst notes section

Admin clicks "Block IP":
    │
    └──► HTTP POST /api/live/sequence/<id>/respond
         Request body: {"action": "block_ip"}
         → IP blocked via iptables / netsh
         → Audit record written
         → 200 OK with result JSON
```

---

## 6. Key Components / Files Involved

| File | Role |
|---|---|
| `flask_app/__init__.py` | Application factory, extension initialisation, blueprint registration |
| `flask_app/config.py` | Config class: session settings, paths, timeouts |
| `flask_app/models.py` | User model (bcrypt, Flask-Login compatible, MongoDB-backed) |
| `flask_app/services/decorators.py` | Centralised RBAC decorators (4 decorators) |
| `flask_app/auth/routes.py` | Login, signup, logout |
| `flask_app/main/routes.py` | All page routes (10 pages + `/admin/response-audit`) |
| `flask_app/admin/routes.py` | Admin settings page |
| `flask_app/api/routes.py` | All JSON REST endpoints (30+ endpoints) |
| `flask_app/ws/events.py` | WebSocket live feed background thread |
| `flask_app/templates/` | Jinja2 HTML templates (subdirectory-organised) |
| `flask_app/static/` | CSS (`main.css`) and JavaScript (6 JS files) |
| `run_flask.py` | Application entry point |

---

## 7. Important Classes / Functions

### `flask_app/models.py` — User Model

```python
class User(UserMixin):
    """
    MongoDB-backed user model, Flask-Login compatible.
    
    Attributes: id, username, email, role, is_active_flag,
                created_at, last_seen
    
    Roles: 'student' | 'analyst' | 'admin'
    """
    
    def check_password(self, password: str) -> bool:
        """bcrypt hash comparison."""
    
    def is_analyst(self) -> bool:
        """Returns True if role is 'analyst' OR 'admin'."""
    
    def is_admin(self) -> bool:
        """Returns True only if role is 'admin'."""
    
    @staticmethod
    def get_by_username(username: str) -> "User | None":
        """Load user from MongoDB by username."""
    
    @staticmethod
    def create(username, email, password, role) -> "User":
        """Create and persist a new user document."""
```

### `flask_app/decorators.py`

```python
def analyst_required(f):
    """Page route decorator: redirects to /login with 403 if not analyst+."""

def admin_required(f):
    """Page route decorator: redirects to /login with 403 if not admin."""

def api_analyst_required(f):
    """API route decorator: returns JSON {error: ...}, 403 if not analyst+."""

def api_admin_required(f):
    """API route decorator: returns JSON {error: ...}, 403 if not admin."""
```

> All four decorators live in `flask_app/services/decorators.py` and are imported by both `main/routes.py` and `api/routes.py`.

### `flask_app/ws/events.py`

```python
@socketio.on("connect", namespace="/ws/live")
def on_connect():
    """Called when a browser client connects to the WebSocket."""
    # Starts the background thread (singleton-guarded)

def _background_feed():
    """Polls MongoDB live_predictions every 12 seconds and emits to browser."""

def _serialize_prediction(doc: dict, role: str) -> dict:
    """Convert MongoDB BSON document to JSON-serialisable dict.
    Redacts src_ip if role is 'student'."""
```

---

## 8. Inputs and Outputs

### Inputs

| Input | Source | Format |
|---|---|---|
| HTTP requests | Browser | HTTP/1.1 |
| WebSocket frames | Browser | Socket.IO protocol |
| Prediction data | MongoDB `live_predictions` | BSON |
| Report data | `reports/*.json` | JSON (cached after first load) |
| User credentials | HTTP POST form | Form data |

### Outputs

| Output | Recipient | Format |
|---|---|---|
| Rendered HTML pages | Browser | HTML (Jinja2 templates) |
| WebSocket events | Browser JS | JSON via Socket.IO |
| REST API responses | Browser JS | JSON |
| CSV export | Browser download | text/csv |
| STIX 2.1 export | Browser download | application/json |

---

## 9. Dependencies

| Dependency | Purpose |
|---|---|
| `flask` | Web framework, routing, request/response |
| `flask-login` | Session management, `current_user`, `@login_required` |
| `flask-socketio` | WebSocket support via Socket.IO |
| `flask-cors` | Cross-origin headers for JavaScript API calls |
| `pymongo` | All MongoDB reads |
| `bson.ObjectId` | Converting MongoDB `_id` to string for JSON |
| `bcrypt` | Password hash verification in `models.py` |
| `jinja2` | Template engine (bundled with Flask) |
| `python-dotenv` | `.env` loading in `config.py` |

---

## 10. Interaction with Other Modules

```
Module 3 (Core Engine)
    │
    ▼
Module 4 (Response / Action)
    │
    ▼
Module 5 (Monitoring / Visualization)  ← YOU ARE HERE
    │
    ├── Reads: live_predictions, attack_campaigns, attacker_profiles,
    │          ip_enrichments, response_audit, canary_triggers
    │
    ├── Displays: all of the above via templates + REST API + WebSocket
    │
    └── Commands Module 4: POST /api/live/sequence/<id>/respond
                          → triggers automated response actions
```

---

## 11. Example Flow / Use Case

**Scenario: Analyst monitors a CRITICAL attack in real time**

```
0. Analyst logs in at /login with role: analyst
   Flask-Login creates session; current_user.role = "analyst"

1. Analyst navigates to /live
   - HTTP GET /live → main_bp renders live.html
   - Page JavaScript connects WebSocket to /ws/live

2. Background thread running in Flask process detects new prediction:
   - MongoDB query finds: risk_level="CRITICAL", src_ip="45.33.32.156"
   - Serialised (src_ip NOT redacted — user is analyst)
   - socketio.emit("new_predictions", [prediction_doc])

3. Browser JavaScript receives the event:
   - Adds new row to the live predictions table
   - Row highlighted in RED (CRITICAL risk)
   - Attack type badge shows "EXPLOIT"

4. Analyst clicks the row
   - GET /live/abc123 → renders sequence_detail.html

5. Browser JavaScript loads detail data:
   - GET /api/live/sequence/abc123
     → Returns full prediction: tokens, scores, MITRE techniques
   - GET /api/live/sequence/abc123/prevention
     → Returns LLM-generated advice:
       access_control: ["Disable root SSH login", "Enforce key-only auth"]
       network_security: ["Block 45.33.32.156", "Rate-limit SSH connections"]
       host_hardening: ["Audit /tmp directory", "Check cron jobs"]

6. Analyst adds a note:
   - POST /api/live/sequence/abc123/notes
     → Stored in MongoDB; visible to all team members

7. Analyst exports for SIEM:
   - GET /api/live/export/stix
     → Downloads stix_bundle_2026-03-10.json (CRITICAL + HIGH only)
```

---

## 12. Configuration Details

### `flask_app/config.py`

```python
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")           # Required; app won't start without it
    MONGO_URI  = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    DB_NAME    = "proactive_deception"

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE   = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 86400   # 1 day in seconds

    # WebSocket
    SOCKETIO_PING_INTERVAL = 10   # Keep-alive ping every 10 seconds
    SOCKETIO_PING_TIMEOUT  = 60   # Disconnect if no pong in 60 seconds

    LIVE_POLL_INTERVAL = 12   # Background thread MongoDB poll interval (seconds)

    REPORTS_DIR = "reports"   # Directory containing evaluation JSON reports
```

### Flask Server (`run_flask.py`)

```bash
# Default: development mode on port 5000
python run_flask.py

# Custom port
PORT=8080 python run_flask.py

# Production mode (enables secure cookies)
FLASK_ENV=production python run_flask.py
```

### Login Manager (`flask_app/__init__.py`)

```python
login_manager.login_view      = "auth.login"     # Redirect target for unauthenticated requests
login_manager.login_message   = "Please log in." # Flash message
login_manager.session_protection = "strong"      # Invalidate session on IP/UA change
```

---

## 13. Implementation Notes

- **Role-based data redaction in WebSocket:** `_serialize_prediction()` in `ws/events.py` checks `current_user.role` at serialisation time. Students receive `src_ip = "*.*.*.*"` — this happens server-side before the JSON leaves the process. There is no client-side filtering.
- **Report caching (`_report_cache`):** The 7 MB `distilbert_evaluation.json` is only parsed from disk once per server process. The cache is process-local (in-memory dict), so it is cleared when the process restarts. This is intentional — reports are regenerated offline; there is never a need for hot-reloading.
- **SocketIO async_mode="threading":** The application uses Flask's development Werkzeug server with threading (not eventlet or gevent). This is acceptable for a research/monitoring context but should be replaced with `async_mode="eventlet"` or `async_mode="gevent"` for production under load.
- **CORS `allow_origins="*"`:** Currently allows any origin to connect to the WebSocket namespace. In a production deployment, this must be restricted to the actual dashboard domain.
- **Blueprint separation:** `admin/routes.py` deliberately contains only one route (`/admin/settings`). This minimal admin blueprint makes it easy to extend — new admin features can be added here without touching `main/routes.py` or `api/routes.py`.
- **Jinja2 and RBAC in templates:** Templates receive `current_user` from Flask-Login. Conditional blocks like `{% if current_user.is_admin() %}` show or hide UI elements. However, **security enforcement always happens at the route level** via decorators — template conditionals are purely cosmetic.
- **ObjectId serialisation:** MongoDB's BSON `ObjectId` type cannot be JSON-serialised natively. All API endpoints convert `_id` fields to strings via `str(doc["_id"])` before returning JSON responses.
