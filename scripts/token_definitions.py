"""
Unified Token Definitions — used by every module in the pipeline.

Maps raw event/syscall names → short canonical token strings, replacing
numeric IDs with readable labels for consistency and debuggability.

Sources covered
---------------
  parse_cowrie.py   — SSH honeypot events
  parse_dionaea.py  — multi-protocol honeypot events
  process_beth.py   — BETH dataset syscall traces
  build_sequences.py — domain-prefix tokens for XLNet

Layout
------
  SPECIAL_TOKENS    Structural tokens  (PAD, UNK, domain prefixes …)
  SYSCALL_TO_TOKEN  Raw syscall → token  (exported; process_beth imports this)
  TOKEN_SHORTCUTS   Master lookup used by get_token():
                      Section A  Cowrie eventid + semantic-type keys
                      Section B  Dionaea-specific event-type keys
                      Section C  SYSCALL_TO_TOKEN merged in
                      Section D  Remaining legacy syscall names (backward compat)
                      Section E  Identity map for every canonical token
                                 (ensures TOKEN_TO_ID is complete & idempotent)
  TOKEN_CATEGORIES  Canonical tokens grouped by behaviour class
  SEVERITY_LEVELS   Risk tier per canonical token
"""

# ── Special / structural tokens ───────────────────────────────────────────────
SPECIAL_TOKENS: dict[str, str] = {
    'PAD':     'PAD',       # Padding token
    'UNK':     'UNK',       # Unknown token (fallback)
    'CLS':     'CLS',       # Classification token  – start of sequence
    'SEP':     'SEP',       # Separator token       – end of sequence
    # Domain-prefix tokens prepended by build_sequences.py / consumed by XLNet
    'BETH':    '[BETH]',
    'COWRIE':  '[COWRIE]',
    'DIONAEA': '[DIONAEA]',
}

# ── SYSCALL_TO_TOKEN ──────────────────────────────────────────────────────────
# Single-tier, authoritative mapping of raw Linux syscall / LSM-hook names
# directly to short ML tokens.  Imported by process_beth.py so the mapping
# is defined exactly once and never duplicated.
SYSCALL_TO_TOKEN: dict[str, str] = {
    # ── Process management ────────────────────────────────────────────────────
    'execve':                   'EXEC',       # exec a new program (literal execute)
    'execveat':                 'EXEC',
    'clone':                    'PROC_EXEC',  # spawn child process
    'clone3':                   'PROC_EXEC',
    'fork':                     'PROC_EXEC',
    'vfork':                    'PROC_EXEC',
    'exit':                     'PROC_EXIT',  # process terminated
    'exit_group':               'PROC_EXIT',
    'kill':                     'PROC_SIG',   # signal sent to process
    'tgkill':                   'PROC_SIG',
    'tkill':                    'PROC_SIG',

    # ── File open / create ────────────────────────────────────────────────────
    'open':                     'FILE_OPEN',
    'openat':                   'FILE_OPEN',
    'openat2':                  'FILE_OPEN',
    'creat':                    'FILE_OPEN',
    'security_file_open':       'FILE_OPEN',  # LSM hook

    # ── File read / stat ──────────────────────────────────────────────────────
    'read':                     'FILE_ACC',
    'pread64':                  'FILE_ACC',
    'readv':                    'FILE_ACC',
    'stat':                     'FILE_ACC',
    'fstat':                    'FILE_ACC',
    'lstat':                    'FILE_ACC',
    'statx':                    'FILE_ACC',
    'access':                   'FILE_ACC',
    'faccessat':                'FILE_ACC',
    'faccessat2':               'FILE_ACC',
    'dup':                      'FILE_ACC',
    'dup2':                     'FILE_ACC',
    'dup3':                     'FILE_ACC',
    'sendfile':                 'FILE_ACC',
    'sendfile64':               'FILE_ACC',
    'getdents':                 'FILE_ACC',
    'getdents64':               'FILE_ACC',

    # ── File write ────────────────────────────────────────────────────────────
    'write':                    'FILE_WRITE',
    'pwrite64':                 'FILE_WRITE',
    'writev':                   'FILE_WRITE',

    # ── File close ────────────────────────────────────────────────────────────
    'close':                    'FILE_CLOSE',

    # ── File delete ───────────────────────────────────────────────────────────
    'unlink':                   'FILE_DEL',
    'unlinkat':                 'FILE_DEL',
    'rmdir':                    'FILE_DEL',
    'security_inode_unlink':    'FILE_DEL',   # LSM hook

    # ── File modify (rename / permission / truncate) ──────────────────────────
    'rename':                   'FILE_MOD',
    'renameat':                 'FILE_MOD',
    'renameat2':                'FILE_MOD',
    'security_inode_rename':    'FILE_MOD',   # LSM hook
    'chmod':                    'FILE_MOD',
    'fchmod':                   'FILE_MOD',
    'fchmodat':                 'FILE_MOD',
    'chown':                    'FILE_MOD',
    'fchown':                   'FILE_MOD',
    'lchown':                   'FILE_MOD',
    'fchownat':                 'FILE_MOD',
    'truncate':                 'FILE_MOD',
    'ftruncate':                'FILE_MOD',

    # ── File / directory create ───────────────────────────────────────────────
    'mknod':                    'FILE_CREAT',
    'mknodat':                  'FILE_CREAT',
    'mkdir':                    'FILE_CREAT',
    'mkdirat':                  'FILE_CREAT',
    'link':                     'FILE_CREAT',
    'linkat':                   'FILE_CREAT',
    'symlink':                  'FILE_CREAT',
    'symlinkat':                'FILE_CREAT',
    'security_inode_create':    'FILE_CREAT', # LSM hook

    # ── Network ───────────────────────────────────────────────────────────────
    'socket':                   'NET_OPEN',   # create socket
    'socketpair':               'NET_OPEN',
    'setsockopt':               'NET_OPEN',
    'getsockopt':               'NET_OPEN',
    'getpeername':              'NET_OPEN',
    'getsockname':              'NET_OPEN',
    'bind':                     'NET_BIND',   # bind to local addr/port
    'security_socket_bind':     'NET_BIND',
    'connect':                  'NET_CONNECT',
    'security_socket_connect':  'NET_CONNECT',
    'accept':                   'NET_ACCEPT',
    'accept4':                  'NET_ACCEPT',
    'security_socket_accept':   'NET_ACCEPT',
    'listen':                   'NET_LISTEN',
    'send':                     'NET_SEND',
    'sendto':                   'NET_SEND',
    'sendmsg':                  'NET_SEND',
    'sendmmsg':                 'NET_SEND',
    'recv':                     'NET_RECV',
    'recvfrom':                 'NET_RECV',
    'recvmsg':                  'NET_RECV',
    'recvmmsg':                 'NET_RECV',
    'shutdown':                 'NET_CLOSE',

    # ── Memory ────────────────────────────────────────────────────────────────
    'mmap':                     'MEM_MAP',
    'mmap2':                    'MEM_MAP',
    'munmap':                   'MEM_MAP',
    'madvise':                  'MEM_MAP',
    'mremap':                   'MEM_MAP',
    'shmat':                    'MEM_MAP',
    'shmdt':                    'MEM_MAP',
    'mprotect':                 'MEM_PROT',   # change memory protection flags
    'brk':                      'MEM_ALLOC',  # extend heap
    'shmget':                   'MEM_ALLOC',
    'shmctl':                   'MEM_ALLOC',

    # ── Privilege / security ──────────────────────────────────────────────────
    'setuid':                   'PRIV_ESC',
    'setgid':                   'PRIV_ESC',
    'setreuid':                 'PRIV_ESC',
    'setregid':                 'PRIV_ESC',
    'setresuid':                'PRIV_ESC',
    'setresgid':                'PRIV_ESC',
    'capset':                   'PRIV_ESC',  # set process capabilities
    'prctl':                    'PRIV_ESC',  # process control (can set no-new-privs)
    'ptrace':                   'PRIV_ESC',  # process tracing / injection
    'seccomp':                  'PRIV_ESC',  # load seccomp filter

    # ── Scheduling / IPC ──────────────────────────────────────────────────────
    'nanosleep':                'SLEEP',
    'sched_yield':              'SLEEP',
    'futex':                    'SYNC',      # fast userspace mutex
    'pipe':                     'IPC',
    'pipe2':                    'IPC',
    'msgget':                   'IPC',
    'msgsnd':                   'IPC',
    'msgrcv':                   'IPC',
    'msgctl':                   'IPC',
    'semget':                   'IPC',
    'semop':                    'IPC',
    'semctl':                   'IPC',
    'eventfd':                  'IPC',
    'eventfd2':                 'IPC',
    'signalfd':                 'IPC',
    'signalfd4':                'IPC',

    # ── System reconnaissance ─────────────────────────────────────────────────
    # Reads OS / process identity — benign by themselves but common in
    # malware that probes the environment before acting.
    'getpid':                   'RECON',
    'getppid':                  'RECON',
    'getuid':                   'RECON',
    'geteuid':                  'RECON',
    'getgid':                   'RECON',
    'getegid':                  'RECON',
    'uname':                    'RECON',
    'sysinfo':                  'RECON',
    'times':                    'RECON',
    'getcwd':                   'RECON',
    'readlink':                 'RECON',
    'readlinkat':               'RECON',
    'getrusage':                'RECON',
    'getrlimit':                'RECON',
}

# ── Master token lookup ───────────────────────────────────────────────────────
TOKEN_SHORTCUTS: dict[str, str] = {

    # ── Section 0: special tokens ─────────────────────────────────────────────
    **SPECIAL_TOKENS,

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  SECTION A — parse_cowrie.py                                        ║
    # ║  Maps raw Cowrie eventid strings and older semantic type names.      ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    # Raw eventid  →  canonical token (parse_cowrie looks these up directly)
    'cowrie.session.connect':       'SCAN',
    'cowrie.client.version':        'RECON',
    'cowrie.client.kex':            'RECON',
    'cowrie.client.size':           'RECON',
    'cowrie.session.params':        'RECON',
    'cowrie.login.failed':          'LOGIN_ATT',
    'cowrie.login.success':         'LOGIN_OK',
    'cowrie.command.input':         'EXEC',
    'cowrie.command.failed':        'EXEC_FAIL',
    'cowrie.session.file_download': 'FILE_XFER',
    'cowrie.session.file_upload':   'FILE_XFER',
    'cowrie.direct-tcpip.request':  'TUNNEL',
    'cowrie.log.closed':            'SESS_END',
    'cowrie.session.closed':        'SESS_END',

    # Semantic event-type names (used by COWRIE_EVENT_TYPES in parse_cowrie)
    'SCAN':           'SCAN',
    'RECONNAISSANCE': 'RECON',
    'LOGIN_ATTEMPT':  'LOGIN_ATT',
    'LOGIN_SUCCESS':  'LOGIN_OK',
    'EXECUTE':        'EXEC',
    'EXECUTE_FAILED': 'EXEC_FAIL',
    'FILE_TRANSFER':  'FILE_XFER',
    'TUNNEL':         'TUNNEL',
    'SESSION_END':    'SESS_END',

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  SECTION B — parse_dionaea.py                                       ║
    # ║  parse_dionaea calls TOKEN_SHORTCUTS.get(event_type, event_type),  ║
    # ║  so all event-type strings it can produce must be mapped here.      ║
    # ║  SCAN and FILE_TRANSFER are already covered in Section A above.     ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    'EXPLOITATION': 'EXPLOITATION',
    'MALWARE':      'MALWARE',

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  SECTION C — process_beth.py  (SYSCALL_TO_TOKEN merged in)         ║
    # ║  process_beth imports SYSCALL_TO_TOKEN directly; including it here  ║
    # ║  also lets get_token() resolve raw syscall names if needed.         ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    **SYSCALL_TO_TOKEN,

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  SECTION D — Legacy syscall names (backward compatibility)          ║
    # ║  These syscalls existed in the old Cowrie pipeline and mapped to    ║
    # ║  PRIV_CHG / NET_SOCK / NET_CONN tokens that predate the BETH path.  ║
    # ║  They are NOT in SYSCALL_TO_TOKEN because BETH does not use them;   ║
    # ║  kept here so old cached records / replay logs still decode.        ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    'seteuid':      'PRIV_CHG',  # set effective UID  (legacy Cowrie path)
    'setegid':      'PRIV_CHG',  # set effective GID
    'cap_capable':  'PRIV_CHG',  # LSM hook: capability check

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  SECTION E — Identity mappings for every canonical token            ║
    # ║  Guarantees:  TOKEN_SHORTCUTS[token] == token  for all tokens.      ║
    # ║  This makes TOKEN_TO_ID complete and get_token() idempotent.        ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    # Special
    'PAD': 'PAD',  'UNK': 'UNK',  'CLS': 'CLS',  'SEP': 'SEP',
    '[BETH]': '[BETH]',  '[COWRIE]': '[COWRIE]',  '[DIONAEA]': '[DIONAEA]',

    # Cowrie
    'RECON': 'RECON',  'LOGIN_ATT': 'LOGIN_ATT',  'LOGIN_OK': 'LOGIN_OK',
    'EXEC':  'EXEC',   'EXEC_FAIL': 'EXEC_FAIL',  'FILE_XFER': 'FILE_XFER',
    'TUNNEL': 'TUNNEL',  'SESS_END': 'SESS_END',

    # Dionaea
    'EXPLOITATION': 'EXPLOITATION',  'MALWARE': 'MALWARE',

    # BETH — process
    'PROC_EXEC': 'PROC_EXEC',  'PROC_EXIT': 'PROC_EXIT',
    'PROC_SIG':  'PROC_SIG',   'PROC_CREATE': 'PROC_CREATE',  # PROC_CREATE: legacy

    # BETH — file
    'FILE_OPEN':  'FILE_OPEN',   'FILE_ACC':   'FILE_ACC',
    'FILE_WRITE': 'FILE_WRITE',  'FILE_CLOSE': 'FILE_CLOSE',
    'FILE_DEL':   'FILE_DEL',    'FILE_MOD':   'FILE_MOD',
    'FILE_CREAT': 'FILE_CREAT',  # BETH canonical  (mknod / mkdir / link …)
    'FILE_CREATE':'FILE_CREATE', # legacy Cowrie syscall path

    # BETH — network
    'NET_OPEN':    'NET_OPEN',    'NET_BIND':    'NET_BIND',
    'NET_CONNECT': 'NET_CONNECT', 'NET_ACCEPT':  'NET_ACCEPT',
    'NET_LISTEN':  'NET_LISTEN',  'NET_SEND':    'NET_SEND',
    'NET_RECV':    'NET_RECV',    'NET_CLOSE':   'NET_CLOSE',
    'NET_SOCK':    'NET_SOCK',    # legacy Cowrie token
    'NET_CONN':    'NET_CONN',    # legacy Cowrie token

    # BETH — memory
    'MEM_MAP': 'MEM_MAP',  'MEM_PROT': 'MEM_PROT',  'MEM_ALLOC': 'MEM_ALLOC',

    # Privilege / permission
    'PRIV_ESC': 'PRIV_ESC',  'PRIV_CHG': 'PRIV_CHG',  'PERM_CHG': 'PERM_CHG',

    # Scheduling / IPC
    'SLEEP': 'SLEEP',  'SYNC': 'SYNC',  'IPC': 'IPC',
}

# ── Reverse mapping: canonical token → first key that resolves to it ──────────
REVERSE_TOKENS: dict[str, str] = {v: k for k, v in TOKEN_SHORTCUTS.items()}

# ── Token categories for behavioural analysis ─────────────────────────────────
TOKEN_CATEGORIES: dict[str, tuple[str, ...]] = {
    'NETWORK': (
        'SCAN', 'RECON', 'TUNNEL',
        'NET_OPEN', 'NET_BIND', 'NET_CONNECT',          # BETH
        'NET_ACCEPT', 'NET_LISTEN', 'NET_SEND',
        'NET_RECV', 'NET_CLOSE',
        'NET_SOCK', 'NET_CONN',                         # legacy Cowrie
    ),
    'EXECUTION': (
        'EXEC', 'EXEC_FAIL',
        'PROC_EXEC', 'PROC_CREATE', 'PROC_EXIT', 'PROC_SIG',
    ),
    'FILE_OPS': (
        'FILE_XFER',
        'FILE_OPEN', 'FILE_ACC', 'FILE_WRITE', 'FILE_CLOSE',
        'FILE_DEL', 'FILE_MOD',
        'FILE_CREAT', 'FILE_CREATE',                    # BETH + legacy
    ),
    'AUTHENTICATION': (
        'LOGIN_ATT', 'LOGIN_OK',
    ),
    'SECURITY': (
        'PRIV_ESC', 'PRIV_CHG', 'PERM_CHG',
        'EXPLOITATION', 'MALWARE',
    ),
    'MEMORY': (
        'MEM_MAP', 'MEM_PROT', 'MEM_ALLOC',
    ),
    'SYSTEM': (
        'SLEEP', 'SYNC', 'IPC',
    ),
    'SESSION': (
        'SESS_END',
    ),
}

# Fast O(1) reverse lookup: token → category name
_TOKEN_TO_CATEGORY: dict[str, str] = {
    token: cat
    for cat, tokens in TOKEN_CATEGORIES.items()
    for token in tokens
}

# ── Severity levels (risk tier per canonical token) ───────────────────────────
SEVERITY_LEVELS: dict[str, str] = {
    # LOW — routine / observational
    'SCAN': 'LOW',   'RECON': 'LOW',    'FILE_ACC':  'LOW',
    'FILE_OPEN': 'LOW', 'FILE_CLOSE': 'LOW',
    'SLEEP': 'LOW',  'SYNC': 'LOW',     'MEM_MAP':   'LOW', 'MEM_ALLOC': 'LOW',

    # MEDIUM — elevated but not immediately dangerous
    'LOGIN_ATT': 'MEDIUM', 'EXEC':     'MEDIUM', 'PROC_EXEC': 'MEDIUM',
    'FILE_XFER': 'MEDIUM', 'PERM_CHG': 'MEDIUM', 'FILE_WRITE':'MEDIUM',
    'FILE_MOD':  'MEDIUM', 'NET_OPEN': 'MEDIUM', 'NET_LISTEN':'MEDIUM',
    'IPC':       'MEDIUM', 'PROC_SIG': 'MEDIUM', 'TUNNEL':    'MEDIUM',

    # HIGH — significant attacker capability or foothold
    'LOGIN_OK':    'HIGH', 'NET_CONN':    'HIGH', 'NET_CONNECT': 'HIGH',
    'NET_BIND':    'HIGH', 'NET_ACCEPT':  'HIGH', 'NET_SEND':    'HIGH',
    'NET_RECV':    'HIGH', 'PRIV_CHG':    'HIGH', 'PRIV_ESC':    'HIGH',
    'PROC_CREATE': 'HIGH', 'FILE_CREATE': 'HIGH', 'FILE_CREAT':  'HIGH',
    'MEM_PROT':    'HIGH', 'EXPLOITATION':'HIGH',

    # CRITICAL — high-impact / destructive
    'EXEC_FAIL': 'CRITICAL', 'FILE_DEL':  'CRITICAL', 'SESS_END':  'CRITICAL',
    'NET_SOCK':  'CRITICAL', 'NET_CLOSE': 'CRITICAL', 'PROC_EXIT': 'CRITICAL',
    'MALWARE':   'CRITICAL',
}

# ── Public helper functions ───────────────────────────────────────────────────

def get_token(event_name: str) -> str:
    """Return the canonical token for *event_name*, or 'UNK'."""
    return TOKEN_SHORTCUTS.get(event_name, 'UNK')


def get_event_name(token: str) -> str:
    """Return the first raw key that maps to *token*, or 'UNK'."""
    return REVERSE_TOKENS.get(token, 'UNK')


def get_severity(token: str) -> str:
    """Return severity tier ('LOW' … 'CRITICAL') for *token*, or 'UNKNOWN'."""
    return SEVERITY_LEVELS.get(token, 'UNKNOWN')


def get_category(token: str) -> str:
    """Return behaviour category for *token* (O(1) lookup), or 'OTHER'."""
    return _TOKEN_TO_CATEGORY.get(token, 'OTHER')


# ── Numeric token IDs for model input ────────────────────────────────────────
# Sorted alphabetically → stable mapping across Python runs / environments.
TOKEN_TO_ID: dict[str, int] = {
    token: idx for idx, token in enumerate(sorted(set(TOKEN_SHORTCUTS.values())))
}
ID_TO_TOKEN: dict[int, str] = {idx: token for token, idx in TOKEN_TO_ID.items()}

# Aggregate statistics — used by build_sequences and model config
TOTAL_TOKENS     = len(TOKEN_SHORTCUTS)      # entries in lookup table
TOTAL_CATEGORIES = len(TOKEN_CATEGORIES)     # behaviour groups
VOCAB_SIZE       = len(TOKEN_TO_ID)          # unique canonical tokens → embedding dim


def get_token_id(token: str) -> int:
    """Return numeric ID for *token*, falling back to UNK's ID."""
    return TOKEN_TO_ID.get(token, TOKEN_TO_ID['UNK'])


def get_token_from_id(token_id: int) -> str:
    """Return canonical token for numeric *token_id*, or 'UNK'."""
    return ID_TO_TOKEN.get(token_id, 'UNK')
