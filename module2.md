# Module 2 — Processing and Analysis Module

---

## 1. Module Name

**Processing and Analysis Module**

---

## 2. Module Purpose

This module transforms **raw, heterogeneous honeypot logs** into **clean, normalised, ML-ready token sequences**. It is the structural backbone between data collection and AI inference.

It serves three distinct functions:

1. **Offline batch processing** — converts raw logs into structured JSON datasets for training
2. **Online incremental parsing** — processes new log lines in real time during live pipeline cycles
3. **Dataset engineering** — splits data, balances classes, and builds final train/val/test files

---

## 3. Problem the Module Solves

Raw honeypot logs are:
- **Heterogeneous** — Cowrie uses JSON, Dionaea uses text, BETH uses CSV
- **Verbose** — single sessions contain hundreds of low-level events
- **Inconsistent in vocabulary** — the same concept (`login attempt`) has different string values across sources

This module solves all three via:
- **Source-specific parsers** that normalise each format
- **A universal token vocabulary** (`token_definitions.py`) that maps every raw event/syscall to a short canonical token
- **A sequence builder** that assembles token lists ready for model input

---

## 4. Detailed Explanation of How It Works

### 4.1 Token Vocabulary — The Single Source of Truth

**File:** `scripts/token_definitions.py`

All parsers, the live pipeline, and the ML models share **one canonical vocabulary** defined in this file. This prevents any terminology drift between training and inference.

```python
# Cowrie event → canonical token
COWRIE_EVENT_TYPES = {
    "cowrie.session.connect":        "SCAN",
    "cowrie.login.failed":           "LOGIN_ATT",
    "cowrie.login.success":          "LOGIN_OK",
    "cowrie.command.input":          "EXEC",
    "cowrie.session.file_download":  "FILE_XFER",
    "cowrie.direct-tcpip.request":   "TUNNEL",
    "cowrie.session.closed":         "SESS_END",
    ...
}

# Linux syscall → canonical token (BETH dataset)
SYSCALL_TO_TOKEN = {
    "execve":    "EXEC",
    "connect":   "NET_CONNECT",
    "open":      "FILE_OPEN",
    "read":      "FILE_READ",
    "write":     "FILE_WRITE",
    "unlink":    "FILE_DEL",
    "setuid":    "PRIV_ESC",
    ...
}
```

Each token has a **severity level** and **category**:

| Token | Category | Severity |
|---|---|---|
| `SCAN` | NETWORK | LOW |
| `LOGIN_ATT` | AUTHENTICATION | MEDIUM |
| `LOGIN_OK` | AUTHENTICATION | HIGH |
| `EXEC` | EXECUTION | HIGH |
| `FILE_XFER` | FILE_OPS | HIGH |
| `TUNNEL` | NETWORK | CRITICAL |
| `PRIV_ESC` | SECURITY | CRITICAL |
| `MALWARE` | EXECUTION | CRITICAL |

**Vocabulary size:** 49 tokens (including 5 special tokens: PAD, UNK, CLS, SEP, and 3 domain prefixes)

### 4.2 Cowrie Batch Parser (`scripts/parse_cowrie.py`)

Reads `data/raw/cowrie/cowrie.json` (JSON Lines format):

```
Step 1: Read every JSON line
Step 2: Group events by session ID
Step 3: Map each eventid → canonical token via COWRIE_EVENT_TYPES
Step 4: Extract session metadata (src_ip, username, hassh, arch, commands)
Step 5: Classify attack type using a priority hierarchy:
        MALWARE > EXPLOIT > BRUTE_FORCE > RECON > SCAN
Step 6: Write to data/processed/cowrie_events.json
```

**Attack classification logic:**
```python
def classify_attack_type(token_set):
    if 'FILE_XFER' in token_set and 'EXEC' in token_set:  return 'MALWARE'
    if 'EXEC' in token_set:                                 return 'EXPLOIT'
    if 'LOGIN_ATT' in token_set and count > 5:             return 'BRUTE_FORCE'
    if client_version_probed:                               return 'RECONNAISSANCE'
    return 'SCAN'
```

### 4.3 Dionaea Batch Parser (`scripts/parse_dionaea.py`)

Reads `data/raw/dionaea/dionaea.log` (text format):

Three-tier event classification:
1. **Named incident pattern** (highest priority): e.g., `shellcode.found` → `EXPLOITATION`
2. **Well-known port number**: e.g., port 445 → `EXPLOITATION` (SMB)
3. **Keyword fallback**: e.g., `malware` anywhere in the line → `MALWARE`

Groups by **Dionaea connection handle** (`con 0x...`) to form sessions equivalent to Cowrie sessions.

**Timestamp parsing note:** Format is `DDMMYYYY HH:MM:SS` — must be parsed to `datetime` objects before sorting, since lexicographic ordering of this format is incorrect.

### 4.4 BETH Dataset Processor (`scripts/process_beth.py`)

Converts Linux kernel syscall traces (CSV) into session sequences:

```
Step 1: Read CSV with only required columns (processId, eventName, timestamp, evil)
Step 2: Vectorised mapping: eventName → token via pd.Series.map(SYSCALL_TO_TOKEN)
Step 3: Group by processId, sort by timestamp within each group
Step 4: Apply sliding-window chunking for long sessions:
        window_size=50 events, stride=25 (50% overlap)
Step 5: Classify attack type from token patterns and ground-truth label
Step 6: Write to data/processed/beth_events.json
```

**Sliding-window chunking logic** (prevents model input overflow at 512 tokens):
```
Process with 120 syscalls:
  Chunk 0: tokens[0:50]
  Chunk 1: tokens[25:75]
  Chunk 2: tokens[50:100]
  Chunk 3: tokens[70:120]  ← tail capture
```

### 4.5 Sequence Dataset Builder (`scripts/build_sequences.py`)

Combines all three parsed sources into unified ML datasets:

```
Step 1: Load beth_events.json, cowrie_events.json, dionaea_events.json
Step 2: Normalise attack type labels to 8 canonical categories:
        BENIGN, BRUTE_FORCE, SCAN, RECONNAISSANCE, EXPLOIT, MALWARE, MIXED
Step 3: Prepend domain prefix token to every sequence:
        [BETH], [COWRIE], [DIONAEA]
Step 4: Stratified, group-level train/val/test split
        (prevents leakage between sliding-window chunks of the same process)
Step 5: Oversample minority class in training set only
Step 6: Write train_sequences.json, val_sequences.json, test_sequences.json
```

**Split ratios:**

| Source | Train | Val | Test |
|---|---|---|---|
| BETH | 70% | 10% | 20% |
| Cowrie | 80% | 10% | 10% |
| Dionaea | 80% | 10% | 10% |

**Domain prefix tokens** allow XLNet to learn domain-conditional next-step distributions:
```
[COWRIE] SCAN LOGIN_ATT LOGIN_ATT LOGIN_OK EXEC FILE_XFER SESS_END
[BETH]   NET_CONNECT FILE_OPEN FILE_READ PRIV_ESC EXEC
[DIONAEA] SCAN EXPLOITATION FILE_TRANSFER
```

### 4.6 Live Incremental Parsers (`live/parse_cowrie.py`, `live/parse_dionaea.py`)

The live equivalents of the batch parsers. Key difference: they are **offset-tracked** — they remember the last log byte position processed and only parse new lines on each call. This avoids re-processing seen events.

```python
def parse_new_events() -> list[dict]:
    """
    1. Load byte offset from MongoDB (`live_state` collection, key: cowrie_offset / dionaea_offset)
    2. Open today's dated log file (data/live_raw/cowrie/YYYY-MM-DD.json)
    3. Seek to stored offset
    4. Parse only new lines from offset to EOF
    5. Update offset in MongoDB
    6. Return new session records
    """
```

### 4.7 Live Sequence Builder (`live/sequence_builder.py`)

Buffers incomplete sessions (where `SESS_END` has not been received yet) and emits complete sequences when:
- `SESS_END` token is observed, OR
- Session timeout fires (> N minutes since last event for this session ID)

Emitted sequences go to `live_sequences` MongoDB collection, ready for Module 3.

---

## 5.1 Live Execution Output — Detailed Observations

> The following output was produced by running the processing pipeline on the actual project data.
> Run commands: `python scripts/process_beth.py` then `python scripts/build_sequences.py`
> Executed: 2026-03-10 (project root, CPU mode)

---

### `process_beth.py` — Full Console Output

```
======================================================================
PROCESSING BETH DATASET
======================================================================

[INFO] Loading labelled_training_data.csv   … 763,141 rows
[INFO] Loading labelled_validation_data.csv … 188,967 rows
[INFO] Loading labelled_testing_data.csv    … 188,967 rows
[OK]   Loaded 1,141,075 total records → 44,742 sessions (windowed)

[OK]   Saved → beth_events.json  (71.4 MB)

Summary:
  Total sessions  : 44,742
  Total events    : 2,229,894
  Malicious       : 6,258
  Benign          : 38,484
  Attack types    : {'BENIGN': 38484, 'MALWARE': 3, 'EXPLOITATION': 6251, 'MALICIOUS': 4}
  Skipped syscalls: {'labelled_training_data.csv': 11819,
                     'labelled_validation_data.csv': 3758,
                     'labelled_testing_data.csv': 1116}
======================================================================
```

**Line-by-line interpretation:**

| Output Line | What It Tells Us |
|---|---|
| `1,141,075 total records` | Raw syscall event count across all three CSV files |
| `44,742 sessions (windowed)` | After grouping by processId and applying sliding-window chunking (window=50, stride=25) |
| `71.4 MB` | Compressed representation — 1.1M rows expanded into 2.2M tracked events but stored efficiently as JSON |
| `Total events: 2,229,894` | Multiple windows per process share overlapping events — overlap_count ≈ 2× raw |
| `Malicious: 6,258` | Only 14% of sessions are labelled malicious — **heavily imbalanced** dataset (addressed in `build_sequences.py`) |
| `EXPLOITATION: 6,251` | Dominant attack type — these are BETH exploit syscall traces |
| `MALICIOUS: 4` | 4 sessions labelled malicious but with unresolved attack type — kept separately |
| `MALWARE: 3` | Rare malware sessions — only 3, critically `build_sequences.py` oversamples these |
| `Skipped syscalls: 11,819 / 3,758 / 1,116` | Syscall names not in `SYSCALL_TO_TOKEN` vocab — mapped to UNK and optionally skipped |

---

### `build_sequences.py` — Full Console Output

```
======================================================================
BUILDING BEHAVIOUR SEQUENCES  (DistilBERT + XLNet)
======================================================================

[1/4] Loading data sources
  [OK] beth_events.json    : 44,742 sequences loaded
  [OK] cowrie_events.json  :    585 sequences loaded
  [OK] dionaea_events.json :    583 sequences loaded

[2/4] Splitting by group (leak-free, stratified)
  BETH    → train 28,264  val  3,428  test 13,050
  Cowrie  → train    468  val     58  test     59
  Dionaea → train    466  val     58  test     59

[3/4] Balancing training set
  Before: BENIGN=28,053  MALICIOUS=1,145
  After : BENIGN=28,053  MALICIOUS=28,053

[4/4] Saving splits
  [OK] Saved → train_sequences.json       (56.7 MB)
  [OK] Saved → val_sequences.json          (4.6 MB)
  [OK] Saved → validation_sequences.json   (4.6 MB)
  [OK] Saved → test_sequences.json        (17.8 MB)

======================================================================
DONE — unified splits ready for DistilBERT + XLNet
======================================================================
  Vocabulary size  : 49
  Max seq length   : 512  (domain prefix included)

  TRAIN
    sequences  : 56,106
    labels     : {0: 28,053,  1: 28,053}
    sources    : {beth: 33,328,  cowrie: 11,594,  dionaea: 11,184}
    attacks    : {BENIGN: 28053, BRUTE_FORCE: 10427, EXPLOIT: 10123,
                  RECONNAISSANCE: 2068, SCAN: 4056, MIXED: 1008, MALWARE: 371}

  VAL
    sequences  : 3,544
    labels     : {0: 3,394,  1: 150}
    sources    : {beth: 3428, cowrie: 58, dionaea: 58}
    attacks    : {BENIGN: 3394, EXPLOIT: 57, BRUTE_FORCE: 49,
                  MALWARE: 1, RECONNAISSANCE: 16, SCAN: 25, MIXED: 2}

  TEST
    sequences  : 13,168
    labels     : {0: 7,037,  1: 6,131}
    sources    : {beth: 13050, cowrie: 59, dionaea: 59}
    attacks    : {BENIGN: 7037, EXPLOIT: 6041, MALWARE: 2,
                  BRUTE_FORCE: 54, RECONNAISSANCE: 11, SCAN: 19, MIXED: 4}
======================================================================
```

**Key observations from the output:**

#### Dataset Imbalance and Oversampling (Step 3)

```
Before: BENIGN=28,053  MALICIOUS=1,145
After : BENIGN=28,053  MALICIOUS=28,053
```

The training data was **~24.5:1 imbalanced** before oversampling (28,053 benign vs 1,145 malicious). Without correction, a model that always predicts BENIGN would achieve ~96% accuracy while being useless. The oversampling step **replicates minority-class sequences** (not synthetic augmentation — actual duplication) until both classes have equal count. This is applied to **training only** — val and test keep natural distribution.

Note: After oversampling, Dionaea and Cowrie malicious sequences also get multiplied:
- `cowrie: 11,594` in train = 468 original × ~24.8× oversampling factor
- `dionaea: 11,184` in train = 466 original × ~24.0× oversampling factor

#### Group-Level Split (Step 2)

```
BETH    → train 28,264  val  3,428  test 13,050
Cowrie  → train    468  val     58  test     59
Dionaea → train    466  val     58  test     59
```

Total BETH sessions = 28,264 + 3,428 + 13,050 = **44,742** ✓ (matches `process_beth.py` output — no sessions dropped)

The split is by `processId`/session group, not individual windows. Because sliding-window chunking creates multiple windows per process, naive splitting would put windows from the same process in both train and test (data leakage). Group-splitting guarantees zero leakage.

Actual ratios achieved:
- Train: 28,264 / 44,742 = **63.2%** (target 70% — slightly lower due to group rounding)
- Val: 3,428 / 44,742 = **7.7%** (target 10%)
- Test: 13,050 / 44,742 = **29.2%** (target 20% — higher because whole groups must stay together)

#### Cowrie Data Volume

```
cowrie_events.json: 585 sequences loaded
Cowrie → train 468  val 58  test 59
```

**585 Cowrie sessions** are available from the live honeypot capture (`data/raw/cowrie/cowrie.json`), producing 585 sessions across 3,163 events. The 80/10/10 split yields 468 training, 58 validation, and 59 test sequences. After oversampling, Cowrie contributes 11,594 sequences to the training set.

The per-source evaluation breakdown correctly shows Cowrie=59 test sequences with 100% accuracy — the model learns the well-defined Cowrie session patterns (SCAN → LOGIN_ATT → LOGIN_OK → EXEC → FILE_XFER).

#### Output File Sizes

| File | Size | Sequences | Avg tokens/seq |
|---|---|---|---|
| `train_sequences.json` | 56.7 MB | 56,106 | ~50.4 |
| `val_sequences.json` | 4.6 MB | 3,544 | ~50.4 |
| `test_sequences.json` | 17.8 MB | 13,168 | ~50.9 |
| `beth_events.json` | 71.4 MB | 44,742 | — |

#### Actual Sequence JSON Schema (from live inspection)

```json
{
  "split": "TRAIN",
  "sequences": [
    {
      "sequence_id": "beth_TRAIN_1234_w0",
      "tokens": ["[BETH]", "FILE_OPEN", "FILE_ACC", "FILE_CLOSE", "FILE_OPEN", ...],
      "label": 0,
      "attack_type": "BENIGN",
      "domain": "beth",
      "length": 51,
      "source_file": "labelled_training_data.csv"
    },
    ...
  ],
  "statistics": {
    "total_sequences": 56106,
    "total_tokens": 2829882,
    "average_length": 50.4,
    "min_length": 2,
    "max_length": 512,
    "vocab_size": 49,
    "label_distribution": {"0": 28053, "1": 28053},
    "attack_distribution": {"BENIGN": 28053, "BRUTE_FORCE": 10427, ...},
    "source_distribution": {"beth": 33328, "cowrie": 11594, "dionaea": 11184}
  }
}
```

---

### Processed Data Files — Actual Sizes

```
data/processed/
  beth_events.json              71.4 MB  ← 44,742 sessions
  cowrie_events.json              ~MB    ← 585 sessions, 3,163 events
  dionaea_events.json              ~MB   ← 583 sessions, 177,918 events
  train_sequences.json          56.7 MB  ← 56,106 sequences (balanced)
  val_sequences.json             4.6 MB  ← 3,544 sequences
  validation_sequences.json      4.6 MB  ← alias of val_sequences.json
  test_sequences.json           17.8 MB  ← 13,168 sequences
```

**Total processed data size: ~155+ MB** (fits easily in RAM for batched inference)

---

## 5. Internal Workflow / Process Flow

```
OFFLINE PIPELINE
────────────────────────────────────────────────────────────────
data/raw/cowrie/cowrie.json
    │
    ▼ scripts/parse_cowrie.py
data/processed/cowrie_events.json
    │
    ├──────────────────────────────────────┐
    │                                      │
data/processed/dionaea_events.json    data/processed/beth_events.json
    │                                      │
    └──────────┬───────────────────────────┘
               ▼ scripts/build_sequences.py
    ┌──────────────────────────────────┐
    │  train_sequences.json  (train)   │
    │  val_sequences.json    (val)     │
    │  test_sequences.json   (test)    │
    └──────────────────────────────────┘

LIVE PIPELINE (every 60 seconds)
────────────────────────────────────────────────────────────────
live/generator.py (every cycle)
    │  generates NEW synthetic Cowrie + Dionaea events
    ├──► data/live_raw/cowrie/YYYY-MM-DD.json   (appended)
    └──► data/live_raw/dionaea/YYYY-MM-DD.json  (appended)
    │
    ▼ live/parse_cowrie.py (incremental, offset-tracked)
    new Cowrie session events
    │
    ▼ live/parse_dionaea.py (incremental, offset-tracked)
    new Dionaea protocol events
    │
    ▼ live/sequence_builder.py (buffer until SESS_END)
    complete token sequences
    │
    ▼ MongoDB: live_sequences collection
    │
    ▼ Module 3 (inference)
```

---

## 6. Key Components / Files Involved

| File | Role |
|---|---|
| `scripts/token_definitions.py` | Master token vocabulary — single source of truth |
| `scripts/parse_cowrie.py` | Batch Cowrie log parser |
| `scripts/parse_dionaea.py` | Batch Dionaea log parser |
| `scripts/process_beth.py` | BETH CSV processor with sliding-window chunking |
| `scripts/build_sequences.py` | Dataset builder (split + balance + domain prefix) |
| `scripts/mitre_mapping.py` | Token → MITRE ATT&CK technique lookup |
| `live/parse_cowrie.py` | Incremental live Cowrie parser |
| `live/parse_dionaea.py` | Incremental live Dionaea parser |
| `live/sequence_builder.py` | Session-buffered online sequence assembler |
| `data/processed/*.json` | All parsed and built datasets |

---

## 7. Important Classes / Functions

### `token_definitions.py`

```python
def get_token(event_id: str) -> str:
    """Map any raw event/syscall name to its canonical token."""

def get_category(token: str) -> str:
    """Return the behavioural category of a token (NETWORK, EXECUTION, ...)."""

def get_severity(token: str) -> str:
    """Return the risk severity of a token (LOW, MEDIUM, HIGH, CRITICAL)."""

def get_token_id(token: str) -> int:
    """Return the numeric ID for a token (used as model input_id)."""

TOKEN_TO_ID: dict[str, int]   # token string → integer
ID_TO_TOKEN: dict[int, str]   # integer → token string
VOCAB_SIZE: int = 49
```

### `build_sequences.py`

```python
def _split_by_group(sequences, ratios, seed) -> tuple[list, list, list]:
    """
    Stratified, leak-free split: groups sliding-window chunks of the same
    process together so they always land in the same split.
    Prevents data leakage between training and evaluation.
    """

def _oversample(sequences, seed) -> list:
    """
    Balance binary classes by resampling the minority class to match the
    majority. Applied to TRAINING set only — val/test use natural distribution.
    """
```

### `process_beth.py`

```python
def load_and_aggregate(data_dir) -> tuple[dict, dict]:
    """
    Load BETH CSV files, group syscalls by processId, apply sliding-window
    chunking, and return (sessions, skip_counts).
    
    Performance optimisations:
    - usecols: only reads required columns
    - pd.Series.map(): vectorised C-speed syscall mapping
    - groupby(sort=False): skips extra sort pass
    """
```

---

## 8. Inputs and Outputs

### Inputs

| Input | Source | Format |
|---|---|---|
| Cowrie raw log (offline training) | `data/raw/cowrie/cowrie.json` | JSON Lines |
| Dionaea raw log (offline training) | `data/raw/dionaea/dionaea.log` | Text |
| BETH CSVs (offline training) | `data/beth/raw/labelled_*.csv` | CSV |
| Live Cowrie events (generator output) | `data/live_raw/cowrie/YYYY-MM-DD.json` | JSON Lines (dated) |
| Live Dionaea events (generator output) | `data/live_raw/dionaea/YYYY-MM-DD.json` | JSON Lines (dated) |

### Outputs

| Output | Location | Format | Consumer |
|---|---|---|---|
| Cowrie events | `data/processed/cowrie_events.json` | JSON | `build_sequences.py` |
| Dionaea events | `data/processed/dionaea_events.json` | JSON | `build_sequences.py` |
| BETH events | `data/processed/beth_events.json` | JSON | `build_sequences.py` |
| Train sequences | `data/processed/train_sequences.json` | JSON | Model training |
| Val sequences | `data/processed/val_sequences.json` | JSON | Model evaluation |
| Test sequences | `data/processed/test_sequences.json` | JSON | `severity_scorer.py` |
| Live sequences | MongoDB `live_sequences` | BSON | `live/inference.py` |

---

## 9. Dependencies

| Dependency | Used By | Purpose |
|---|---|---|
| `json` | All parsers | Reading/writing JSON |
| `pandas` | `process_beth.py` | Vectorised CSV processing |
| `re` | `parse_dionaea.py` | Regex timestamp and IP extraction |
| `pathlib.Path` | All parsers | Platform-safe file paths |
| `collections.defaultdict` | All parsers | Session-grouping accumulator |
| `pymongo` | `sequence_builder.py` | Live sequence writes, offset state |
| `token_definitions` | All parsers | Canonical token lookup |

---

## 10. Interaction with Other Modules

```
Module 1 (Data Collection)
        │  produces raw logs
        ▼
Module 2 (Processing / Analysis)    ← YOU ARE HERE
        │  produces token sequences
        ▼
Module 3 (Core Engine / Detection)
        │  consumes sequences via MongoDB live_sequences or JSON files
```

- **Receives from Module 1:** Raw log files in `data/raw/` and `data/live_raw/`
- **Sends to Module 3:** Structured token sequences in `data/processed/*.json` (offline) and MongoDB `live_sequences` collection (live)
- **Sends to Module 5:** MITRE ATT&CK mappings (via `mitre_mapping.py` imported by `inference.py`)

---

## 11. Example Flow / Use Case

**Example: BETH syscall trace → ML-ready sequence**

```
Raw CSV row:
  processId=1234, eventName="execve", timestamp=1.5, evil=1

After processing:
  Token:   EXEC
  Label:   1 (MALICIOUS)

Full process session (50 syscalls after windowing):
  Tokens: [BETH] NET_CONNECT FILE_OPEN FILE_READ PRIV_ESC EXEC NET_SEND ...

Stored in train_sequences.json:
{
  "sequence_id": "beth_TRAIN_1234_w0",
  "tokens": ["[BETH]", "NET_CONNECT", "FILE_OPEN", "FILE_READ", "PRIV_ESC", "EXEC", ...],
  "label": 1,
  "attack_type": "EXPLOITATION",
  "domain": "beth",
  "length": 50
}
```

---

## 12. Configuration Details

### `build_sequences.py` Constants

```python
MAX_SEQ_LEN  = 512   # Maximum tokens per sequence (model input cap)
RANDOM_SEED  = 42    # Reproducibility seed
BETH_SPLIT   = (0.70, 0.10, 0.20)   # Train/val/test for BETH
HON_SPLIT    = (0.80, 0.10, 0.10)   # Train/val/test for honeypots

DOMAIN_PREFIX = {
    'beth':    '[BETH]',
    'cowrie':  '[COWRIE]',
    'dionaea': '[DIONAEA]',
}
```

### `process_beth.py` Constants

```python
WINDOW_SIZE = 50   # Events per sliding window chunk
STRIDE      = 25   # Step size (50% overlap between consecutive chunks)
```

### Running the Offline Pipeline

```bash
# Parse raw logs (run from project root)
python scripts/parse_cowrie.py
python scripts/parse_dionaea.py
python scripts/process_beth.py

# Build ML datasets
python scripts/build_sequences.py
```

---

## 13. Implementation Notes

- **Single source of truth:** `token_definitions.py` is intentionally the **only** place where event-to-token mappings exist. Both offline scripts and live pipeline import from it. Any new event type must be added here.
- **Group-level split prevents leakage:** Naive random split would put window 3 of process 1234 into training and window 5 of the same process into test. `_split_by_group()` prevents this by guaranteeing all windows of the same process land in the same split.
- **Tail-truncation in live mode:** When a live sequence exceeds MAX_SEQ_LEN, the **tail** is kept (most recent tokens), not the head. This is because the most recent actions are more relevant for attack classification.
- **val_sequences.json is saved twice** — once as `val_sequences.json` and once as `validation_sequences.json` (alias). Both training scripts may expect either name; both are written for compatibility.
- **Live offset persistence:** The byte offset into the log file is stored in MongoDB so the incremental parser never re-processes lines even after a crash.
