# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Python AST visitor — tiered heuristics with scoped capability extraction.

Implements the PESSIMISTIC scope extraction model:
- String literals → resolved directly
- Simple string constant concatenation → resolved
- EVERYTHING ELSE → scope=["*"], scope_resolved=False

Never resolves variables, f-strings with variables, function calls, etc.

Enrichment: every Finding is annotated with source code, function context,
CWE/OWASP references, risk notes, and tags for both human and agent
consumption.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Optional

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── CWE / OWASP / tag metadata for capability categories ──────────
# Default mapping by (category, action) → (cwe_ids, owasp_ids, tags).
# Specific patterns can override via PATTERN_CWE_OVERRIDES below.

CATEGORY_CWE_DEFAULTS: dict[tuple[str, str], tuple[list[str], list[str], list[str]]] = {
    # Filesystem
    ("fs", "read"): (["CWE-22"], ["A01:2021"], ["filesystem", "path-traversal"]),
    ("fs", "write"): (["CWE-22", "CWE-73"], ["A01:2021"], ["filesystem", "arbitrary-write"]),
    ("fs", "delete"): (["CWE-22"], ["A01:2021"], ["filesystem", "data-destruction"]),
    # Network
    ("network", "connect"): (["CWE-918"], ["A10:2021"], ["ssrf", "network"]),
    ("network", "listen"): (["CWE-200"], ["A01:2021"], ["network", "open-port"]),
    ("network", "dns"): (["CWE-918"], ["A10:2021"], ["network", "dns"]),
    # Subprocess
    ("subprocess", "exec"): (["CWE-78"], ["A03:2021"], ["command-injection"]),
    ("subprocess", "spawn"): (["CWE-78"], ["A03:2021"], ["command-injection"]),
    # Environment
    ("env", "read"): (["CWE-200"], ["A02:2021"], ["info-exposure", "env-read"]),
    ("env", "write"): (["CWE-15"], ["A05:2021"], ["env-manipulation"]),
    # Browser
    ("browser", "control"): (["CWE-269"], ["A01:2021"], ["browser-automation"]),
    ("browser", "navigate"): (["CWE-601"], ["A01:2021"], ["browser-automation"]),
    # Secrets
    ("secret", "access"): (["CWE-312"], ["A02:2021"], ["credential-access"]),
    ("secret", "store"): (["CWE-312"], ["A02:2021"], ["credential-store"]),
    # Crypto
    ("crypto", "hash"): (["CWE-328"], ["A02:2021"], ["crypto"]),
    ("crypto", "sign"): (["CWE-347"], ["A02:2021"], ["crypto"]),
    ("crypto", "encrypt"): (["CWE-327"], ["A02:2021"], ["crypto"]),
    # Serialization
    ("serial", "deserialize"): (["CWE-502"], ["A08:2021"], ["deserialization"]),
    # Concurrency
    ("concurrency", "thread"): (["CWE-362"], [], ["concurrency"]),
    ("concurrency", "process"): (["CWE-362"], [], ["concurrency"]),
    ("concurrency", "async"): ([], [], ["concurrency", "async"]),
    # System
    ("system", "signal"): (["CWE-364"], [], ["system", "signal-handler"]),
    ("system", "sysinfo"): (["CWE-200"], [], ["system", "info-exposure"]),
}

# Pattern-specific CWE overrides — more precise than category defaults.
PATTERN_CWE_OVERRIDES: dict[str, tuple[list[str], list[str], list[str]]] = {
    # Prohibited patterns
    "eval": (["CWE-95"], ["A03:2021"], ["code-injection", "dynamic-exec"]),
    "exec": (["CWE-95"], ["A03:2021"], ["code-injection", "dynamic-exec"]),
    "compile": (["CWE-95"], ["A03:2021"], ["code-injection", "dynamic-exec"]),
    "importlib.import_module": (["CWE-94"], ["A03:2021"], ["code-injection", "dynamic-import"]),
    "__import__": (["CWE-94"], ["A03:2021"], ["code-injection", "dynamic-import"]),
    # Deserialization sinks
    "pickle.load": (["CWE-502"], ["A08:2021"], ["deserialization", "pickle", "rce-risk"]),
    "pickle.loads": (["CWE-502"], ["A08:2021"], ["deserialization", "pickle", "rce-risk"]),
    "marshal.load": (["CWE-502"], ["A08:2021"], ["deserialization", "marshal"]),
    "marshal.loads": (["CWE-502"], ["A08:2021"], ["deserialization", "marshal"]),
    "yaml.load": (["CWE-502"], ["A08:2021"], ["deserialization", "yaml", "rce-risk"]),
    "yaml.load_all": (["CWE-502"], ["A08:2021"], ["deserialization", "yaml", "rce-risk"]),
    "yaml.unsafe_load": (["CWE-502"], ["A08:2021"], ["deserialization", "yaml", "rce-risk"]),
    "yaml.unsafe_load_all": (["CWE-502"], ["A08:2021"], ["deserialization", "yaml", "rce-risk"]),
    "shelve.open": (["CWE-502"], ["A08:2021"], ["deserialization", "shelve"]),
    "shelve.DbfilenameShelf": (["CWE-502"], ["A08:2021"], ["deserialization", "shelve"]),
    # XML (XXE)
    "xml.etree.ElementTree.parse": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "xml.etree.ElementTree.fromstring": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "xml.etree.cElementTree.parse": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "xml.etree.cElementTree.fromstring": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "lxml.etree.parse": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "lxml.etree.fromstring": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    "xml.sax.parse": (["CWE-611"], ["A05:2021"], ["xxe", "xml"]),
    # Weak randomness
    "random.random": (["CWE-330"], ["A02:2021"], ["weak-random", "predictable"]),
    "random.randint": (["CWE-330"], ["A02:2021"], ["weak-random", "predictable"]),
    "random.choice": (["CWE-330"], ["A02:2021"], ["weak-random", "predictable"]),
    "random.randrange": (["CWE-330"], ["A02:2021"], ["weak-random", "predictable"]),
    # Temp file race
    "tempfile.mktemp": (["CWE-377"], ["A01:2021"], ["toctou", "race-condition"]),
    # Archive handling
    "zipfile.ZipFile": (["CWE-409"], ["A01:2021"], ["archive-bomb", "zip"]),
    "tarfile.open": (["CWE-409"], ["A01:2021"], ["archive-bomb", "tar"]),
    "shutil.unpack_archive": (["CWE-409"], ["A01:2021"], ["archive-bomb"]),
    # SSRF patterns
    "urllib.request.urlopen": (["CWE-918"], ["A10:2021"], ["ssrf", "network"]),
    "urllib.request.Request": (["CWE-918"], ["A10:2021"], ["ssrf", "network"]),
    # Introspection
    "sys._getframe": (["CWE-209"], ["A04:2021"], ["introspection", "info-leak"]),
    "sys.settrace": (["CWE-209"], ["A04:2021"], ["introspection", "tracing"]),
    "inspect.stack": (["CWE-209"], ["A04:2021"], ["introspection", "info-leak"]),
    "gc.get_objects": (["CWE-209"], ["A04:2021"], ["introspection", "info-leak"]),
    # Database connections
    "psycopg2.connect": (["CWE-918"], ["A10:2021"], ["database", "network"]),
    "pymysql.connect": (["CWE-918"], ["A10:2021"], ["database", "network"]),
    "pymongo.MongoClient": (["CWE-918"], ["A10:2021"], ["database", "network"]),
    "redis.Redis": (["CWE-918"], ["A10:2021"], ["database", "network"]),
    "sqlalchemy.create_engine": (["CWE-918"], ["A10:2021"], ["database", "network"]),
    "sqlite3.connect": (["CWE-22"], ["A01:2021"], ["database", "filesystem"]),
    # FFI
    "ctypes": (["CWE-120"], ["A03:2021"], ["ffi", "memory-corruption"]),
    "cffi.FFI": (["CWE-120"], ["A03:2021"], ["ffi", "memory-corruption"]),
    # Signal handlers
    "signal.signal": (["CWE-364"], [], ["signal-handler", "persistence"]),
    # Privilege manipulation
    "os.setuid": (["CWE-250"], ["A01:2021"], ["privilege-escalation"]),
    "os.setgid": (["CWE-250"], ["A01:2021"], ["privilege-escalation"]),
    "os.chroot": (["CWE-250"], ["A01:2021"], ["privilege-escalation", "sandbox-escape"]),
    # sys.path manipulation
    "sys.path.insert": (["CWE-427"], ["A08:2021"], ["module-hijack", "supply-chain"]),
    "sys.path.append": (["CWE-427"], ["A08:2021"], ["module-hijack", "supply-chain"]),
    # Memory-mapped I/O
    "mmap.mmap": (["CWE-119"], ["A06:2021"], ["memory-mapped-io", "ffi"]),
    # Code object construction
    "types.CodeType": (["CWE-95"], ["A03:2021"], ["code-injection", "code-object"]),
    "types.FunctionType": (["CWE-95"], ["A03:2021"], ["code-injection", "code-object"]),
    # Dynamic module loading from file path
    "importlib.util.spec_from_file_location": (["CWE-94"], ["A03:2021"], ["code-injection", "dynamic-import"]),
    "importlib.util.module_from_spec": (["CWE-94"], ["A03:2021"], ["code-injection", "dynamic-import"]),
    "importlib.reload": (["CWE-94"], ["A08:2021"], ["code-injection", "dynamic-import"]),
    # File descriptor manipulation
    "os.pipe": (["CWE-200"], [], ["fd-manipulation"]),
    "os.dup": (["CWE-200"], [], ["fd-manipulation"]),
    "os.dup2": (["CWE-200"], [], ["fd-manipulation"]),
    # Hashlib specifics
    "hashlib.md5": (["CWE-328"], ["A02:2021"], ["crypto", "weak-hash"]),
    "hashlib.sha1": (["CWE-328"], ["A02:2021"], ["crypto", "weak-hash"]),
    "hashlib.sha256": ([], [], ["crypto"]),
    "hashlib.sha512": ([], [], ["crypto"]),
}


# ── Rich human-readable messages per pattern ──────────────────────
# These replace generic "Restricted call: X" with actionable descriptions.
# {scope} and {target} are format placeholders filled at runtime.

RICH_MESSAGES: dict[str, str] = {
    # Network - HTTP
    "requests.get": "Outbound HTTP GET{target} — reads data from external endpoint",
    "requests.post": "Outbound HTTP POST{target} — sends data to external endpoint",
    "requests.put": "Outbound HTTP PUT{target} — sends data to external endpoint",
    "requests.delete": "Outbound HTTP DELETE{target} — modifies external resource",
    "requests.patch": "Outbound HTTP PATCH{target} — modifies external resource",
    "requests.head": "Outbound HTTP HEAD{target} — probes external endpoint",
    "requests.request": "HTTP request{target} — flexible HTTP method",
    "requests.Session": "HTTP session creation — persistent connections with cookie jar",
    "httpx.get": "Outbound HTTP GET{target} — reads data from external endpoint",
    "httpx.post": "Outbound HTTP POST{target} — sends data to external endpoint",
    "httpx.put": "Outbound HTTP PUT{target} — sends data to external endpoint",
    "httpx.delete": "Outbound HTTP DELETE{target} — modifies external resource",
    "httpx.patch": "Outbound HTTP PATCH{target} — modifies external resource",
    "httpx.head": "Outbound HTTP HEAD{target} — probes external endpoint",
    "httpx.request": "HTTP request{target} — flexible HTTP method",
    "httpx.Client": "HTTP client creation — persistent connections for multiple requests",
    "httpx.AsyncClient": "Async HTTP client — concurrent network requests",
    "aiohttp.ClientSession": "Async HTTP session — concurrent network requests",
    # Network - low-level
    "socket.socket": "Raw socket creation — low-level network access",
    "socket.create_connection": "TCP connection — low-level network access",
    "socket.getaddrinfo": "DNS resolution — maps hostnames to IP addresses",
    "socket.gethostbyname": "DNS lookup — resolves hostname to IP address",
    # Network - databases
    "psycopg2.connect": "PostgreSQL database connection{target}",
    "psycopg.connect": "PostgreSQL database connection{target}",
    "pymysql.connect": "MySQL database connection{target}",
    "pymongo.MongoClient": "MongoDB database connection{target}",
    "redis.Redis": "Redis connection{target} — in-memory data store",
    "redis.StrictRedis": "Redis connection{target} — in-memory data store",
    "sqlalchemy.create_engine": "SQLAlchemy database engine{target} — ORM database access",
    "sqlite3.connect": "SQLite database{target} — local file-based database",
    # Network - servers
    "http.server.HTTPServer": "HTTP server — listening for inbound connections",
    "socketserver.TCPServer": "TCP server — listening for inbound connections",
    "asyncio.start_server": "Async TCP server — listening for inbound connections",
    # Network - protocols
    "ftplib.FTP": "FTP connection{target} — cleartext file transfer (insecure)",
    "smtplib.SMTP": "SMTP connection{target} — email sending",
    "imaplib.IMAP4": "IMAP connection{target} — email inbox access",
    "paramiko.SSHClient": "SSH connection{target} — remote server access",
    # Network - cloud
    "boto3.client": "AWS service client — cloud API access",
    "boto3.resource": "AWS resource access — cloud infrastructure",
    "google.cloud.storage.Client": "Google Cloud Storage client",
    # Subprocess
    "subprocess.run": "Command execution{target} via subprocess.run()",
    "subprocess.call": "Command execution{target} via subprocess.call()",
    "subprocess.check_call": "Command execution{target} via subprocess.check_call()",
    "subprocess.check_output": "Command execution{target} via subprocess.check_output()",
    "subprocess.Popen": "Process launch{target} via subprocess.Popen()",
    "os.system": "Shell command execution{target} via os.system()",
    "os.popen": "Shell pipe{target} via os.popen()",
    "asyncio.create_subprocess_exec": "Async command execution{target}",
    "asyncio.create_subprocess_shell": "Async shell command{target}",
    # Filesystem
    "os.remove": "File deletion{target}",
    "os.unlink": "File deletion{target}",
    "os.rmdir": "Directory deletion{target}",
    "os.removedirs": "Recursive directory deletion{target}",
    "os.rename": "File rename/move{target}",
    "os.replace": "File replacement{target}",
    "os.makedirs": "Directory tree creation{target}",
    "os.mkdir": "Directory creation{target}",
    "os.symlink": "Symbolic link creation{target}",
    "os.link": "Hard link creation{target}",
    "os.chmod": "File permission change{target}",
    "os.chown": "File ownership change{target}",
    "os.listdir": "Directory listing{target}",
    "os.scandir": "Directory scan{target}",
    "os.walk": "Recursive directory traversal{target}",
    "os.stat": "File metadata read{target}",
    "os.path.exists": "File existence check{target}",
    "glob.glob": "Path globbing{target} — finds files matching pattern",
    # Environment
    "os.environ": "Environment variable access — reads process environment",
    "os.getenv": "Environment variable read{target}",
    "os.environ.get": "Environment variable read{target}",
    "os.putenv": "Environment variable write{target}",
    "os.unsetenv": "Environment variable deletion{target}",
    # Secrets
    "keyring.get_password": "Keychain read{target} — retrieves stored credential",
    "keyring.set_password": "Keychain write{target} — stores credential",
    "dotenv.load_dotenv": "Loading .env file — reads secrets from dotenv",
    "load_dotenv": "Loading .env file — reads secrets from dotenv",
    # Crypto
    "hashlib.sha256": "SHA-256 hash computation",
    "hashlib.sha512": "SHA-512 hash computation",
    "hashlib.sha1": "SHA-1 hash computation (weak — collisions demonstrated)",
    "hashlib.md5": "MD5 hash computation (broken — do not use for security)",
    "hashlib.new": "Hash computation via hashlib.new()",
    "hashlib.pbkdf2_hmac": "PBKDF2 key derivation — password hashing",
    "hmac.new": "HMAC creation — keyed message authentication",
    "jwt.encode": "JWT token creation — signing authentication token",
    "jwt.decode": "JWT token verification — decoding authentication token",
    # System
    "signal.signal": "Signal handler — intercepts OS signals (e.g., Ctrl+C)",
    "os.kill": "Process signal{target} — sends signal to another process",
    "platform.system": "OS detection — reads operating system name",
    "platform.uname": "System fingerprinting — detailed OS/hardware info",
    "platform.node": "Hostname detection — reads machine network name",
    "atexit.register": "Exit handler — runs code when Python exits",
    # Browser
    "webbrowser.open": "Browser launch{target} — opens URL in system browser",
    # Concurrency
    "threading.Thread": "Thread creation — enables concurrent background execution",
    "multiprocessing.Process": "Process creation — launches separate OS process",
    "multiprocessing.Pool": "Process pool — concurrent multi-process execution",
    "concurrent.futures.ThreadPoolExecutor": "Thread pool — concurrent task execution",
    "concurrent.futures.ProcessPoolExecutor": "Process pool — concurrent task execution",
    "asyncio.create_task": "Async task — concurrent coroutine execution",
    "asyncio.gather": "Async gather — runs multiple coroutines concurrently",
    # Legacy/dangerous
    "pty.spawn": "Pseudo-terminal spawn — common in reverse shells",
    "commands.getoutput": "Legacy shell execution (Python 2)",
    "runpy.run_path": "Dynamic file execution{target} — runs Python file as module",
    "runpy.run_module": "Dynamic module execution{target} — runs module by name",
    # Evasion / privilege / memory
    "mmap.mmap": "Memory-mapped file I/O — direct memory access bypassing normal file APIs",
    "cffi.FFI": "Foreign function interface — direct C library access, memory corruption risk",
    "os.setuid": "Privilege manipulation — changing user ID",
    "os.setgid": "Privilege manipulation — changing group ID",
    "os.seteuid": "Privilege manipulation — changing effective user ID",
    "os.setegid": "Privilege manipulation — changing effective group ID",
    "os.chroot": "Chroot manipulation — potential sandbox escape vector",
    "os.pipe": "File descriptor pipe creation — inter-process communication",
    "os.dup": "File descriptor duplication — can redirect I/O streams",
    "os.dup2": "File descriptor duplication — can redirect stdin/stdout/stderr",
    "sys.path.insert": "Module search path manipulation — can load malicious modules",
    "sys.path.append": "Module search path manipulation — can load malicious modules",
    "importlib.util.spec_from_file_location": "Dynamic module loading from file path — code injection risk",
    "importlib.util.module_from_spec": "Dynamic module construction — code injection risk",
    "importlib.reload": "Dynamic module reloading — can replace module contents at runtime",
    "types.CodeType": "Code object construction — executes code without calling eval/exec",
    "types.FunctionType": "Function object construction from code object — indirect code execution",
    "aiofiles.open": "Async file I/O — filesystem access via aiofiles",
}


# ── Risk notes explain "why THIS matters HERE" ────────────────────
# Generated dynamically based on scope resolution.

def _format_target(scope: list[str], resolved: bool) -> str:
    """Format a scope list into a readable target suffix for messages."""
    if not scope or scope == ["*"] or not resolved:
        return ""
    if len(scope) == 1:
        return f" '{scope[0]}'"
    return f" [{', '.join(scope[:3])}{'...' if len(scope) > 3 else ''}]"


def _make_risk_note(
    pattern: str,
    scope: list[str],
    resolved: bool,
    category: str,
    action: str,
) -> str:
    """Generate a context-aware risk note explaining why this finding matters."""
    if not resolved or (scope and scope[0] == "*"):
        # Unresolved scope — the big concern
        scope_warning = {
            "fs": "File path is dynamic — Aegis cannot verify which files are accessed. Could target credentials, configs, or system files.",
            "network": "URL/host is dynamic — Aegis cannot verify the target endpoint. Could connect to attacker-controlled servers (SSRF).",
            "subprocess": "Command is dynamic — Aegis cannot verify what program runs. Any executable on the system could be invoked.",
            "env": "Environment variable name is dynamic — could access any secret in the process environment.",
            "browser": "Browser target is dynamic — could navigate to any URL including authenticated sessions.",
            "secret": "Credential target is dynamic — could access any stored secret.",
            "serial": "Deserialized data source is unknown — untrusted data deserialization enables arbitrary code execution.",
        }
        return scope_warning.get(category, "Target is dynamic — scope cannot be verified by static analysis.")

    # Resolved scope — lower risk, provide context
    scope_str = ", ".join(scope[:3])
    resolved_notes = {
        "fs": f"Targets: {scope_str}. Verify these paths are expected and within the project directory.",
        "network": f"Targets: {scope_str}. Verify this is a trusted endpoint.",
        "subprocess": f"Executes: {scope_str}. Verify this is the intended command.",
        "env": f"Reads: {scope_str}. Verify this env var is documented and expected.",
        "browser": f"Navigates to: {scope_str}. Verify this URL is trusted.",
    }
    return resolved_notes.get(category, f"Targets: {scope_str}.")


def _get_rich_message(
    call_name: str,
    scope: list[str],
    resolved: bool,
    category: str,
    action: str,
) -> str:
    """Generate a human-readable message for a finding.

    Checks RICH_MESSAGES first, then falls back to a category-based default.
    """
    target = _format_target(scope, resolved)

    # Check pattern-specific messages
    if call_name in RICH_MESSAGES:
        msg = RICH_MESSAGES[call_name].format(target=target)
        if not resolved and scope == ["*"]:
            msg += " (target unresolved)"
        return msg

    # Category-based fallback
    category_labels = {
        "fs": f"Filesystem {action}{target}",
        "network": f"Network {action}{target}",
        "subprocess": f"Command execution{target}",
        "env": f"Environment {action}{target}",
        "browser": f"Browser {action}{target}",
        "secret": f"Credential {action}{target}",
        "crypto": f"Cryptographic {action}",
        "serial": f"Data deserialization{target}",
        "concurrency": f"Concurrent {action}",
        "system": f"System {action}",
    }
    msg = category_labels.get(category, f"{call_name}{target}")
    if not resolved and scope == ["*"]:
        msg += " (target unresolved)"
    return msg


def _lookup_cwe(pattern: str, category: str = "", action: str = "") -> tuple[list[str], list[str], list[str]]:
    """Look up CWE IDs, OWASP refs, and tags for a pattern.

    Returns (cwe_ids, owasp_ids, tags).
    Checks pattern-specific overrides first, then category defaults.
    """
    if pattern in PATTERN_CWE_OVERRIDES:
        return PATTERN_CWE_OVERRIDES[pattern]
    # Try base name (e.g., "subprocess.run" → check "subprocess.run")
    if ":" in pattern:
        base = pattern.split(":")[0]
        if base in PATTERN_CWE_OVERRIDES:
            return PATTERN_CWE_OVERRIDES[base]
    if category and action:
        return CATEGORY_CWE_DEFAULTS.get((category, action), ([], [], []))
    return ([], [], [])

# ── Prohibited patterns: hard fail, no override ──

PROHIBITED_FUNCTIONS = {
    "eval": "Dynamic code execution via eval()",
    "exec": "Dynamic code execution via exec()",
    "compile": "Dynamic code compilation via compile()",
    "execfile": "Dynamic code execution via execfile() (Python 2 legacy)",
}

# Modules where any import is itself prohibited (extreme risk)
PROHIBITED_MODULES = {
    "commands": "Python 2 shell execution module (commands) — effectively unmitigated shell exec",
    "pty": "Pseudo-terminal module (pty) — used for shell spawning / reverse shells",
}

PROHIBITED_MODULES_FUNCTIONS = {
    ("importlib", "import_module"): "Dynamic import via importlib.import_module()",
    ("ctypes",): "FFI/foreign function interface via ctypes",
    ("commands", "getoutput"): "Shell execution via commands.getoutput() (Python 2 legacy)",
    ("commands", "getstatusoutput"): "Shell execution via commands.getstatusoutput() (Python 2 legacy)",
    ("pty", "spawn"): "Process execution via pty.spawn() — common in reverse shells",
    ("posix", "system"): "Direct system call via posix.system() — bypasses os module abstraction",
    ("posix", "popen"): "Direct pipe via posix.popen() — bypasses os module abstraction",
}

# Modules where getattr(<module>, <variable>) is prohibited because it
# allows dynamic access to dangerous functions (os.system, subprocess.run, etc.)
DANGEROUS_GETATTR_MODULES = frozenset({
    "os", "sys", "subprocess", "builtins", "__builtins__",
    "importlib", "ctypes", "cffi", "signal", "shutil", "socket",
    "types", "marshal", "pickle", "mmap",
})

# ── Restricted pattern mappings ──
# Maps (module_or_name, function_pattern) → (category, action)

RESTRICTED_CALL_PATTERNS: dict[str, tuple[CapabilityCategory, CapabilityAction]] = {
    # Filesystem
    "open": (CapabilityCategory.FS, CapabilityAction.READ),
    "io.open": (CapabilityCategory.FS, CapabilityAction.READ),
    # Network
    "requests.get": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.post": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.put": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.delete": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.patch": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.head": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.request": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests.Session": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.get": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.post": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.put": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.delete": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.patch": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.head": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.request": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.Client": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx.AsyncClient": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "urllib.request.urlopen": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "urllib.request.urlretrieve": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "urllib.request.Request": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "socket.socket": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "socket.create_connection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # Subprocess
    "subprocess.run": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "subprocess.call": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "subprocess.check_call": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "subprocess.check_output": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "subprocess.Popen": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.system": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.popen": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execvp": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execv": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execve": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execl": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execle": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execlp": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execlpe": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.execvpe": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "os.spawnl": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnle": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnlp": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnlpe": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnv": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnve": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnvp": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    "os.spawnvpe": (CapabilityCategory.SUBPROCESS, CapabilityAction.SPAWN),
    # Environment
    "os.environ": (CapabilityCategory.ENV, CapabilityAction.READ),
    "os.getenv": (CapabilityCategory.ENV, CapabilityAction.READ),
    # Browser control
    "selenium.webdriver": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "playwright.sync_api": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "playwright.async_api": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "mechanize.Browser": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "splinter.Browser": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "pyppeteer.launch": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    # Secrets
    "keyring.get_password": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "keyring.set_password": (CapabilityCategory.SECRET, CapabilityAction.STORE),
    "secretstorage": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "hvac.Client": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "dotenv.load_dotenv": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "dotenv.dotenv_values": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "dotenv_values": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "load_dotenv": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    # Deserialization
    "pickle.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "pickle.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "marshal.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "marshal.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "shelve.open": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "shelve.DbfilenameShelf": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "yaml.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "yaml.unsafe_load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "yaml.load_all": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "yaml.unsafe_load_all": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "jsonpickle.decode": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "jsonpickle.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "dill.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "dill.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "cloudpickle.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "cloudpickle.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # XML parsing (XXE risk)
    "xml.etree.ElementTree.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.etree.ElementTree.fromstring": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.etree.cElementTree.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.etree.cElementTree.fromstring": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "lxml.etree.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "lxml.etree.fromstring": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.dom.minidom.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.dom.minidom.parseString": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.sax.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xmltodict.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # Concurrency
    "threading.Thread": (CapabilityCategory.CONCURRENCY, CapabilityAction.THREAD),
    "multiprocessing.Process": (CapabilityCategory.CONCURRENCY, CapabilityAction.PROCESS),
    "multiprocessing.Pool": (CapabilityCategory.CONCURRENCY, CapabilityAction.PROCESS),
    "concurrent.futures.ThreadPoolExecutor": (CapabilityCategory.CONCURRENCY, CapabilityAction.THREAD),
    "concurrent.futures.ProcessPoolExecutor": (CapabilityCategory.CONCURRENCY, CapabilityAction.PROCESS),
    "asyncio.gather": (CapabilityCategory.CONCURRENCY, CapabilityAction.ASYNC),
    "asyncio.create_task": (CapabilityCategory.CONCURRENCY, CapabilityAction.ASYNC),
    "asyncio.ensure_future": (CapabilityCategory.CONCURRENCY, CapabilityAction.ASYNC),
    # System
    "signal.signal": (CapabilityCategory.SYSTEM, CapabilityAction.SIGNAL),
    "os.kill": (CapabilityCategory.SYSTEM, CapabilityAction.SIGNAL),
    "os.killpg": (CapabilityCategory.SYSTEM, CapabilityAction.SIGNAL),
    "atexit.register": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "platform.system": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "platform.node": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "platform.platform": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "platform.uname": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Async networking ──
    "aiohttp.ClientSession": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "aiohttp.request": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "asyncio.open_connection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "asyncio.start_server": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── Async subprocess ──
    "asyncio.create_subprocess_exec": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "asyncio.create_subprocess_shell": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    # ── Stdlib networking (http.client, ftp, smtp, xmlrpc) ──
    "http.client.HTTPConnection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "http.client.HTTPSConnection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "http.server.HTTPServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "http.server.ThreadingHTTPServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "socketserver.TCPServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "socketserver.UDPServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "socketserver.ThreadingTCPServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "ftplib.FTP": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "ftplib.FTP_TLS": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "smtplib.SMTP": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "smtplib.SMTP_SSL": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "imaplib.IMAP4": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "imaplib.IMAP4_SSL": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "poplib.POP3": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "poplib.POP3_SSL": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "xmlrpc.client.ServerProxy": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # ── Third-party networking (SSH, cloud, web frameworks) ──
    "paramiko.SSHClient": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "paramiko.Transport": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "fabric.Connection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "tornado.httpclient.AsyncHTTPClient": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "tornado.httpclient.HTTPClient": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # ── WebSocket libraries ──
    "websocket.WebSocket": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "websocket.create_connection": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "websockets.connect": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "websockets.serve": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── gRPC ──
    "grpc.insecure_channel": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "grpc.secure_channel": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "grpc.server": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── Database clients (network connect) ──
    "psycopg2.connect": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "psycopg.connect": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "pymysql.connect": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "mysql.connector.connect": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "pymongo.MongoClient": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "redis.Redis": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "redis.StrictRedis": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "elasticsearch.Elasticsearch": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "cassandra.cluster.Cluster": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "sqlalchemy.create_engine": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "sqlalchemy.engine.create_engine": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "sqlite3.connect": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── DNS ──
    "dns.resolver.resolve": (CapabilityCategory.NETWORK, CapabilityAction.DNS),
    "dns.resolver.query": (CapabilityCategory.NETWORK, CapabilityAction.DNS),
    "socket.getaddrinfo": (CapabilityCategory.NETWORK, CapabilityAction.DNS),
    "socket.gethostbyname": (CapabilityCategory.NETWORK, CapabilityAction.DNS),
    # ── Cloud SDKs ──
    "boto3.client": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "boto3.resource": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "boto3.Session": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "google.cloud.storage.Client": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "google.cloud.bigquery.Client": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "google.cloud.secretmanager.SecretManagerServiceClient": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "azure.identity.DefaultAzureCredential": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "azure.keyvault.secrets.SecretClient": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    # ── Browser (stdlib) ──
    "webbrowser.open": (CapabilityCategory.BROWSER, CapabilityAction.NAVIGATE),
    "webbrowser.open_new": (CapabilityCategory.BROWSER, CapabilityAction.NAVIGATE),
    "webbrowser.open_new_tab": (CapabilityCategory.BROWSER, CapabilityAction.NAVIGATE),
    # ── OS file operations ──
    "os.remove": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "os.unlink": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "os.rmdir": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "os.removedirs": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "os.rename": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.replace": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.makedirs": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.mkdir": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.symlink": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.link": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.chmod": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.chown": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.listdir": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.scandir": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.walk": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.stat": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.path.exists": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.path.isfile": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.path.isdir": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.access": (CapabilityCategory.FS, CapabilityAction.READ),
    "glob.glob": (CapabilityCategory.FS, CapabilityAction.READ),
    "glob.iglob": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── OS environment ──
    "os.environ.get": (CapabilityCategory.ENV, CapabilityAction.READ),
    "os.putenv": (CapabilityCategory.ENV, CapabilityAction.WRITE),
    "os.unsetenv": (CapabilityCategory.ENV, CapabilityAction.WRITE),
    # ── Tempfile ──
    "tempfile.mktemp": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "tempfile.mkdtemp": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "tempfile.mkstemp": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "tempfile.NamedTemporaryFile": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "tempfile.TemporaryDirectory": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "tempfile.SpooledTemporaryFile": (CapabilityCategory.FS, CapabilityAction.WRITE),
    # ── Crypto ──
    "cryptography.fernet.Fernet": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "cryptography.hazmat.primitives.ciphers.Cipher": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "hashlib.sha256": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hashlib.sha512": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hashlib.sha1": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hashlib.md5": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hashlib.new": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hashlib.pbkdf2_hmac": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hmac.new": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "hmac.digest": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "jwt.encode": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "jwt.decode": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "Crypto.Cipher.AES.new": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "Crypto.PublicKey.RSA.generate": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "nacl.secret.SecretBox": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "nacl.public.PrivateKey": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "rsa.encrypt": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "rsa.sign": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    # ── Windows registry ──
    "winreg.OpenKey": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "winreg.SetValueEx": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "winreg.CreateKey": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "winreg.DeleteKey": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Legacy / low-level execution sinks (from PDF research) ──
    "platform.popen": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "posix.system": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "posix.popen": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "pty.spawn": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "pty.openpty": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "pty.fork": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "commands.getoutput": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "commands.getstatusoutput": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    # ── Dynamic execution / metaprogramming ──
    "runpy.run_path": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "runpy.run_module": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "code.InteractiveInterpreter": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "code.InteractiveConsole": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "codeop.CommandCompiler": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Introspection / frame access ──
    "sys._getframe": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "sys.settrace": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "sys.setprofile": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "inspect.currentframe": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "inspect.stack": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "inspect.getframeinfo": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "gc.get_objects": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "gc.get_referrers": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── sqlite3 special sinks ──
    "sqlite3.connect": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── multiprocessing deserialization sinks ──
    "multiprocessing.connection.Listener": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "multiprocessing.Pipe": (CapabilityCategory.CONCURRENCY, CapabilityAction.PROCESS),
    # ── Weak randomness ──
    "random.random": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.randint": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.choice": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.randrange": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.uniform": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.getrandbits": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "random.sample": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    # ── Archive extraction (bomb risk) ──
    "zipfile.ZipFile": (CapabilityCategory.FS, CapabilityAction.READ),
    "tarfile.open": (CapabilityCategory.FS, CapabilityAction.READ),
    "shutil.unpack_archive": (CapabilityCategory.FS, CapabilityAction.WRITE),
    # ── Network servers (xmlrpc) ──
    "xmlrpc.server.SimpleXMLRPCServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "xmlrpc.server.CGIXMLRPCRequestHandler": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── plistlib (XXE risk on older Python) ──
    "plistlib.load": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "plistlib.loads": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # ── XML pulldom / sax additional ──
    "xml.dom.pulldom.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.dom.pulldom.parseString": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xml.sax.parseString": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # Short aliases (for `from xml.dom import pulldom; pulldom.parse(...)` etc.)
    "pulldom.parse": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "pulldom.parseString": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # Short aliases for xmlrpc.server classes
    "SimpleXMLRPCServer": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    "CGIXMLRPCRequestHandler": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── Async file I/O (aiofiles) ──
    "aiofiles.open": (CapabilityCategory.FS, CapabilityAction.READ),
    "aiofiles.os.remove": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "aiofiles.os.rename": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "aiofiles.os.mkdir": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "aiofiles.os.rmdir": (CapabilityCategory.FS, CapabilityAction.DELETE),
    "aiofiles.os.stat": (CapabilityCategory.FS, CapabilityAction.READ),
    "aiofiles.os.listdir": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── Memory-mapped I/O ──
    "mmap.mmap": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── FFI (cffi) ──
    "cffi.FFI": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Privilege manipulation ──
    "os.setuid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.setgid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.seteuid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.setegid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.chroot": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.getuid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.getgid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.geteuid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.getegid": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "os.getlogin": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── File descriptor manipulation ──
    "os.pipe": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "os.dup": (CapabilityCategory.FS, CapabilityAction.READ),
    "os.dup2": (CapabilityCategory.FS, CapabilityAction.WRITE),
    # ── sys.path manipulation ──
    "sys.path.insert": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "sys.path.append": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Dynamic module loading ──
    "importlib.util.spec_from_file_location": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "importlib.util.module_from_spec": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "importlib.reload": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    # ── Code object construction ──
    "types.CodeType": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "types.FunctionType": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
}

# Import-level restricted patterns
RESTRICTED_IMPORTS: dict[str, tuple[CapabilityCategory, CapabilityAction]] = {
    "os": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "subprocess": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "socket": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "requests": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "httpx": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "urllib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "selenium": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "playwright": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "keyring": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "secretstorage": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "pickle": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "marshal": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "shelve": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "threading": (CapabilityCategory.CONCURRENCY, CapabilityAction.THREAD),
    "multiprocessing": (CapabilityCategory.CONCURRENCY, CapabilityAction.PROCESS),
    "signal": (CapabilityCategory.SYSTEM, CapabilityAction.SIGNAL),
    # ── Async / third-party networking ──
    "aiohttp": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "paramiko": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "fabric": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "tornado": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "twisted": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # ── Cloud SDKs ──
    "boto3": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "botocore": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # ── Stdlib networking ──
    "ftplib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "smtplib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "telnetlib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "xmlrpc": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "imaplib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "poplib": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "socketserver": (CapabilityCategory.NETWORK, CapabilityAction.LISTEN),
    # ── WebSocket / gRPC / messaging ──
    "websocket": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "websockets": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "grpc": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    # ── Database clients ──
    "psycopg2": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "psycopg": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "pymysql": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "pymongo": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "redis": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "elasticsearch": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "cassandra": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "sqlalchemy": (CapabilityCategory.NETWORK, CapabilityAction.CONNECT),
    "sqlite3": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── Browser / filesystem / crypto ──
    "webbrowser": (CapabilityCategory.BROWSER, CapabilityAction.NAVIGATE),
    "mechanize": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "splinter": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "pyppeteer": (CapabilityCategory.BROWSER, CapabilityAction.CONTROL),
    "tempfile": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "shutil": (CapabilityCategory.FS, CapabilityAction.WRITE),
    "glob": (CapabilityCategory.FS, CapabilityAction.READ),
    "io": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── Crypto ──
    "cryptography": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "hashlib": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    "hmac": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "jwt": (CapabilityCategory.CRYPTO, CapabilityAction.SIGN),
    "Crypto": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "nacl": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    "rsa": (CapabilityCategory.CRYPTO, CapabilityAction.ENCRYPT),
    # ── Serialization ──
    "dill": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "cloudpickle": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "jsonpickle": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "xmltodict": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    "lxml": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
    # ── Secrets / vault ──
    "hvac": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    "dotenv": (CapabilityCategory.SECRET, CapabilityAction.ACCESS),
    # ── Concurrency ──
    "concurrent": (CapabilityCategory.CONCURRENCY, CapabilityAction.THREAD),
    # ── System / platform ──
    "platform": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "atexit": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "winreg": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "syslog": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Legacy / low-level execution (from PDF research) ──
    "commands": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "pty": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "posix": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    "runpy": (CapabilityCategory.SUBPROCESS, CapabilityAction.EXEC),
    # ── Metaprogramming / introspection ──
    "code": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "codeop": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "inspect": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    "gc": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Weak randomness ──
    "random": (CapabilityCategory.CRYPTO, CapabilityAction.HASH),
    # ── Async file I/O ──
    "aiofiles": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── FFI ──
    "cffi": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Memory-mapped I/O ──
    "mmap": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── Code construction / metaprogramming ──
    "types": (CapabilityCategory.SYSTEM, CapabilityAction.SYSINFO),
    # ── Archive handling (bomb risk) ──
    "zipfile": (CapabilityCategory.FS, CapabilityAction.READ),
    "tarfile": (CapabilityCategory.FS, CapabilityAction.READ),
    # ── plistlib ──
    "plistlib": (CapabilityCategory.SERIAL, CapabilityAction.DESERIALIZE),
}


# ── Modules where import-level findings are suppressed ──
# These are common stdlib modules that are innocuous to import.
# The import itself is NOT a finding — only actual dangerous CALLS are findings.
# Capabilities are still tracked internally for the capability map.
SUPPRESSED_IMPORT_MODULES = frozenset({
    "os", "sys", "platform", "random", "hashlib", "hmac", "signal",
    "io", "glob", "tempfile", "shutil", "sqlite3", "zipfile", "tarfile",
    "inspect", "gc", "atexit", "code", "codeop", "plistlib",
    "types", "mmap",
})

# Subprocess calls that need special scope extraction (binary name parsing).
# The generic restricted-call handler should skip these.
_SUBPROCESS_SPECIAL_CASES = frozenset({
    "open",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    # Legacy / low-level execution sinks (from PDF research)
    "platform.popen",
    "posix.system",
    "posix.popen",
    "pty.spawn",
    "commands.getoutput",
    "commands.getstatusoutput",
    "runpy.run_path",
    "runpy.run_module",
})

# Subprocess calls that support shell=True
_SHELL_TRUE_CALLABLES = frozenset({
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
})

# Weak random functions — flag when used in security-sensitive contexts
_WEAK_RANDOM_FUNCS = frozenset({
    "random.random",
    "random.randint",
    "random.choice",
    "random.randrange",
    "random.uniform",
    "random.getrandbits",
    "random.sample",
    "random.shuffle",
    "random.choices",
})

# Variable name fragments that suggest security-sensitive context
_SECURITY_CONTEXT_NAMES = frozenset({
    "token", "key", "secret", "password", "pass", "auth",
    "session", "nonce", "salt", "otp", "pin", "credential",
})

# Introspection calls that should be flagged as RESTRICTED (high-risk system)
_INTROSPECTION_CALLS = frozenset({
    "sys._getframe",
    "sys.settrace",
    "sys.setprofile",
    "inspect.currentframe",
    "inspect.stack",
    "inspect.getframeinfo",
    "gc.get_objects",
    "gc.get_referrers",
})

# Calls that suggest embedded REPL / debug console — PROHIBITED in production
_REPL_CALLS = frozenset({
    "code.InteractiveInterpreter",
    "code.InteractiveConsole",
    "code.interact",
    "codeop.CommandCompiler",
})

_TAINT_SOURCE_CALLS = frozenset({
    "input",
    "os.getenv",
    "os.environ.get",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.json.get",
    "request.cookies.get",
    "request.headers.get",
})

_TAINT_COMMAND_SINKS = frozenset({
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "posix.system",
    "posix.popen",
})

_TAINT_URL_SINKS = frozenset({
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "httpx.head",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
})

_TAINT_PATH_SINKS = frozenset({
    "open",
    "os.path.join",
    "pathlib.Path.open",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.rename",
    "os.replace",
    "os.mkdir",
    "os.makedirs",
    "shutil.rmtree",
    "shutil.move",
})


def try_extract_literal(node: ast.expr) -> tuple[str, bool]:
    """PESSIMISTIC scope extraction from an AST node.

    Returns (scope_value, scope_resolved).

    ONLY resolves:
    - String literal (ast.Constant with str value)
    - Simple concatenation of string constants (BinOp Add of two Constant str)

    EVERYTHING ELSE returns ("*", False).
    Never resolves variables, f-strings with variables, function calls, etc.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value, True)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_val, left_ok = try_extract_literal(node.left)
        right_val, right_ok = try_extract_literal(node.right)
        if left_ok and right_ok:
            return (left_val + right_val, True)

    # EVERYTHING ELSE: variables, f-strings, function calls, attribute access,
    # subscripts, ternaries, etc. → pessimistic wildcard
    return ("*", False)


def _get_call_name(node: ast.Call, import_aliases: Optional[dict[str, str]] = None) -> Optional[str]:
    """Extract the callable name from a Call node.

    Returns dotted names like 'requests.get', 'os.system', 'open'.
    Returns None for complex expressions.
    """
    import_aliases = import_aliases or {}

    def _apply_alias(raw_name: str) -> str:
        parts = raw_name.split(".")
        if not parts:
            return raw_name
        mapped = import_aliases.get(parts[0])
        if not mapped:
            return raw_name
        if len(parts) == 1:
            return mapped
        return ".".join([mapped, *parts[1:]])

    if isinstance(node.func, ast.Name):
        return _apply_alias(node.func.id)
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return _apply_alias(".".join(reversed(parts)))
    return None


def _detect_open_mode(node: ast.Call) -> CapabilityAction:
    """Determine if an open() call is read or write based on mode argument."""
    # Default mode is 'r' (read)
    mode = "r"

    # Check positional args (mode is the 2nd argument)
    if len(node.args) >= 2:
        mode_val, resolved = try_extract_literal(node.args[1])
        if resolved:
            mode = mode_val

    # Check keyword args
    for kw in node.keywords:
        if kw.arg == "mode":
            mode_val, resolved = try_extract_literal(kw.value)
            if resolved:
                mode = mode_val

    write_modes = {"w", "a", "x", "r+", "w+", "a+", "x+", "wb", "ab", "xb", "r+b", "w+b"}
    if any(m in mode for m in write_modes):
        return CapabilityAction.WRITE

    return CapabilityAction.READ


def _extract_first_arg_scope(node: ast.Call) -> tuple[list[str], bool]:
    """Extract scope from the first argument of a call."""
    if node.args:
        value, resolved = try_extract_literal(node.args[0])
        return [value], resolved

    # Check for common keyword arguments
    for kw in node.keywords:
        if kw.arg in ("url", "path", "file", "filename", "cmd"):
            value, resolved = try_extract_literal(kw.value)
            return [value], resolved

    return ["*"], False


def _is_safe_yaml_loader_expr(node: ast.expr) -> bool:
    """Return True when the expression clearly references a safe PyYAML loader."""
    if isinstance(node, ast.Attribute):
        return node.attr in {"SafeLoader", "CSafeLoader"}
    if isinstance(node, ast.Name):
        return node.id in {"SafeLoader", "CSafeLoader"}
    return False


def _extract_subprocess_scope(node: ast.Call) -> tuple[list[str], bool]:
    """Extract binary name and args from subprocess calls."""
    if not node.args:
        return ["*"], False

    first_arg = node.args[0]

    # subprocess.run(["git", "status"]) — list literal
    if isinstance(first_arg, ast.List) and first_arg.elts:
        values = []
        all_resolved = True
        for elt in first_arg.elts:
            val, resolved = try_extract_literal(elt)
            values.append(val)
            if not resolved:
                all_resolved = False
        return values, all_resolved

    # subprocess.run("git status") or os.system("git status") — string
    val, resolved = try_extract_literal(first_arg)
    if resolved:
        # Split command string to get binary name
        parts = val.split()
        return parts, True

    return ["*"], False


def _check_base64_exec_pattern(node: ast.Call, call_name: str) -> Optional[Finding]:
    """Detect base64/hex decoding fed into execution functions."""
    # Check if exec/eval wraps a decode call
    if call_name in ("exec", "eval") and node.args:
        arg = node.args[0]
        if isinstance(arg, ast.Call):
            inner_name = _get_call_name(arg)
            if inner_name and any(
                p in inner_name
                for p in ("b64decode", "b64encode", "decode", "fromhex", "unhexlify")
            ):
                return Finding(
                    file="",  # filled in by caller
                    line=node.lineno,
                    col=node.col_offset,
                    pattern=f"{call_name}({inner_name}(...))",
                    severity=FindingSeverity.PROHIBITED,
                    message="Base64/hex decoding fed into execution function — obfuscated code execution",
                )
    return None


class AegisASTVisitor(ast.NodeVisitor):
    """AST visitor that extracts capabilities and detects prohibited patterns.

    Produces two lists:
    - prohibited_findings: hard failures (eval, exec, compile, ctypes, etc.)
    - restricted_findings: flagged capabilities with scoped extraction

    Enrichment: every finding is annotated with source code text, enclosing
    function/class context, CWE/OWASP references, risk notes, and tags.
    """

    def __init__(self, filename: str, source_lines: list[str] | None = None) -> None:
        self.filename = filename
        self.prohibited_findings: list[Finding] = []
        self.restricted_findings: list[Finding] = []
        self.capabilities: list[ScopedCapability] = []
        # Context findings: suppressed import-level findings that still feed the capability map
        # but are NOT counted in report card finding counts or displayed in findings table
        self.context_findings: list[Finding] = []
        # ── Enrichment state ──
        self._source_lines = source_lines or []
        self._context_stack: list[str] = []  # function/class name stack
        # Import alias map: local symbol -> fully qualified module/object.
        # Examples:
        #   import os as sys_ops        => {"sys_ops": "os"}
        #   from subprocess import run as r => {"r": "subprocess.run"}
        self._import_aliases: dict[str, str] = {}
        # Lightweight taint state: variable names observed to carry untrusted input.
        self._tainted_names: set[str] = set()
        # Lightweight interprocedural signal: function names that return tainted data.
        self._tainted_return_functions: set[str] = set()
        self._function_name_stack: list[str] = []

    def _resolve_alias_name(self, name: str) -> str:
        parts = name.split(".")
        if not parts:
            return name
        mapped = self._import_aliases.get(parts[0])
        if not mapped:
            return name
        if len(parts) == 1:
            return mapped
        return ".".join([mapped, *parts[1:]])

    def _is_request_derived(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id == "request"
        if isinstance(node, ast.Attribute):
            root = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                root.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                chain = [cur.id, *reversed(root)]
                if chain[0] == "request" and len(chain) >= 2:
                    return chain[1] in {"args", "form", "values", "json", "data", "files", "headers", "cookies"}
        return False

    def _is_taint_source_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute):
            full_name = self._resolve_alias_name(
                _get_call_name(ast.Call(func=node, args=[], keywords=[]), self._import_aliases) or ""
            )
            if full_name in {"sys.argv", "os.environ"}:
                return True

        if isinstance(node, ast.Call):
            call_name = _get_call_name(node, self._import_aliases)
            if call_name and call_name in _TAINT_SOURCE_CALLS:
                return True
            if call_name and call_name.split(".")[-1] in self._tainted_return_functions:
                return True
        if isinstance(node, ast.Subscript):
            # sys.argv[...] and os.environ[...] are untrusted input.
            if isinstance(node.value, ast.Attribute):
                attr_name = _get_call_name(ast.Call(func=node.value, args=[], keywords=[]), self._import_aliases)
                if attr_name in {"sys.argv", "os.environ"}:
                    return True
            if self._is_request_derived(node.value):
                return True
        if self._is_request_derived(node):
            return True
        return False

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_taint_source_expr(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self._tainted_names
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(k) for k in node.keys if k is not None) or any(
                self._expr_is_tainted(v) for v in node.values
            )
        if isinstance(node, ast.Call):
            # Taint flows through function outputs when any argument is tainted.
            if any(self._expr_is_tainted(a) for a in node.args):
                return True
            if any(self._expr_is_tainted(kw.value) for kw in node.keywords):
                return True
            return self._is_taint_source_expr(node)
        return False

    def _mark_tainted_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._tainted_names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_tainted_target(elt)

    def _sink_input_is_tainted(
        self,
        node: ast.Call,
        *,
        positional_indices: tuple[int, ...] = (0,),
        keyword_names: tuple[str, ...] = (),
    ) -> bool:
        for idx in positional_indices:
            if idx < len(node.args) and self._expr_is_tainted(node.args[idx]):
                return True
        for kw in node.keywords:
            if kw.arg and kw.arg in keyword_names and self._expr_is_tainted(kw.value):
                return True
        return False

    # ── Context tracking ──────────────────────────────────────────

    @property
    def _current_context(self) -> str:
        """Return the current enclosing function/class context, e.g. 'MyClass.deploy'."""
        return ".".join(self._context_stack) if self._context_stack else ""

    def _get_source_line(self, lineno: int) -> str:
        """Extract a source line by 1-indexed line number."""
        if self._source_lines and 0 < lineno <= len(self._source_lines):
            return self._source_lines[lineno - 1].rstrip()
        return ""

    def _get_end_pos(self, node: ast.AST) -> tuple[int, int]:
        """Extract end_lineno and end_col_offset from an AST node."""
        end_line = getattr(node, "end_lineno", 0) or 0
        end_col = getattr(node, "end_col_offset", 0) or 0
        return end_line, end_col

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function context for finding enrichment."""
        self._function_name_stack.append(node.name)
        self._context_stack.append(f"{node.name}()")
        self.generic_visit(node)
        self._context_stack.pop()
        self._function_name_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function context for finding enrichment."""
        self._function_name_stack.append(node.name)
        self._context_stack.append(f"async {node.name}()")
        self.generic_visit(node)
        self._context_stack.pop()
        self._function_name_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class context for finding enrichment."""
        self._context_stack.append(node.name)
        self.generic_visit(node)
        self._context_stack.pop()

    # ── Import visitors ───────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        """Detect restricted and prohibited module imports."""
        end_line, end_col = self._get_end_pos(node)
        source = self._get_source_line(node.lineno)

        for alias in node.names:
            if alias.asname:
                # import xml.etree.ElementTree as ET -> ET => xml.etree.ElementTree
                self._import_aliases[alias.asname] = alias.name
            else:
                # import urllib.request -> local symbol is "urllib"
                # Keep canonical root mapping to avoid over-expanding
                root_name = alias.name.split(".")[0]
                self._import_aliases[root_name] = root_name

            module_name = alias.name.split(".")[0]

            # Check prohibited modules first
            if module_name in PROHIBITED_MODULES:
                cwe, owasp, tags = _lookup_cwe(module_name, "subprocess", "exec")
                self.prohibited_findings.append(
                    Finding(
                        file=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        end_line=end_line,
                        end_col=end_col,
                        pattern=f"import {alias.name}",
                        severity=FindingSeverity.PROHIBITED,
                        message=PROHIBITED_MODULES[module_name],
                        source_line=source,
                        function_context=self._current_context,
                        cwe_ids=list(cwe),
                        owasp_ids=list(owasp),
                        tags=list(tags) + ["import"],
                        risk_note=f"Importing '{module_name}' is itself dangerous — this module provides direct access to dangerous system capabilities.",
                    )
                )

            if module_name in RESTRICTED_IMPORTS:
                cat, action = RESTRICTED_IMPORTS[module_name]
                cap = ScopedCapability(
                    category=cat,
                    action=action,
                    scope=["*"],
                    scope_resolved=False,
                )
                # Track the capability always
                self.capabilities.append(cap)
                cwe, owasp, tags = _lookup_cwe(
                    f"import {alias.name}", cat.value, action.value
                )

                finding = Finding(
                    file=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    end_line=end_line,
                    end_col=end_col,
                    pattern=f"import {alias.name}",
                    severity=FindingSeverity.RESTRICTED,
                    capability=cap,
                    message=f"Imports '{alias.name}' — enables {cat.value}:{action.value} capabilities. Actual risk depends on usage.",
                    source_line=source,
                    function_context=self._current_context,
                    cwe_ids=list(cwe),
                    owasp_ids=list(owasp),
                    tags=list(tags) + ["import"],
                    confidence="medium",  # import alone is lower confidence than a call
                    risk_note=f"The import itself grants access to {cat.value} operations. Check if the module's dangerous APIs are actually called.",
                )

                # Suppress finding for innocuous stdlib imports — only track capability
                if module_name in SUPPRESSED_IMPORT_MODULES:
                    self.context_findings.append(finding)
                else:
                    self.restricted_findings.append(finding)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect restricted and prohibited from-imports."""
        if node.module:
            module_name = node.module.split(".")[0]
            end_line, end_col = self._get_end_pos(node)
            source = self._get_source_line(node.lineno)
            names = ", ".join(a.name for a in (node.names or []))

            for alias in node.names or []:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                self._import_aliases[local_name] = f"{node.module}.{alias.name}"

            # Check prohibited modules first
            if module_name in PROHIBITED_MODULES:
                cwe, owasp, tags = _lookup_cwe(module_name, "subprocess", "exec")
                self.prohibited_findings.append(
                    Finding(
                        file=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        end_line=end_line,
                        end_col=end_col,
                        pattern=f"from {node.module} import {names}",
                        severity=FindingSeverity.PROHIBITED,
                        message=PROHIBITED_MODULES[module_name],
                        source_line=source,
                        function_context=self._current_context,
                        cwe_ids=list(cwe),
                        owasp_ids=list(owasp),
                        tags=list(tags) + ["import"],
                        risk_note=f"Importing from '{module_name}' is itself dangerous — this module provides direct access to dangerous system capabilities.",
                    )
                )

            if module_name in RESTRICTED_IMPORTS:
                cat, action = RESTRICTED_IMPORTS[module_name]
                cap = ScopedCapability(
                    category=cat,
                    action=action,
                    scope=["*"],
                    scope_resolved=False,
                )
                # Track the capability always
                self.capabilities.append(cap)
                cwe, owasp, tags = _lookup_cwe(
                    f"from {node.module} import", cat.value, action.value
                )

                finding = Finding(
                    file=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    end_line=end_line,
                    end_col=end_col,
                    pattern=f"from {node.module} import {names}",
                    severity=FindingSeverity.RESTRICTED,
                    capability=cap,
                    message=f"Imports '{names}' from '{node.module}' — enables {cat.value}:{action.value} capabilities. Actual risk depends on usage.",
                    source_line=source,
                    function_context=self._current_context,
                    cwe_ids=list(cwe),
                    owasp_ids=list(owasp),
                    tags=list(tags) + ["import"],
                    confidence="medium",
                    risk_note=f"This import grants access to {cat.value} operations. Check if the imported names are used for dangerous operations.",
                )

                # Suppress finding for innocuous stdlib imports — only track capability
                if module_name in SUPPRESSED_IMPORT_MODULES:
                    self.context_findings.append(finding)
                else:
                    self.restricted_findings.append(finding)

            # Check for dynamic import_module
            if node.module == "importlib":
                for alias in node.names or []:
                    if alias.name == "import_module":
                        cwe, owasp, tags = _lookup_cwe("importlib.import_module")
                        self.prohibited_findings.append(
                            Finding(
                                file=self.filename,
                                line=node.lineno,
                                col=node.col_offset,
                                end_line=end_line,
                                end_col=end_col,
                                pattern="from importlib import import_module",
                                severity=FindingSeverity.PROHIBITED,
                                message="Dynamic import via importlib.import_module() — can load any module at runtime, bypassing static analysis",
                                source_line=source,
                                function_context=self._current_context,
                                cwe_ids=list(cwe),
                                owasp_ids=list(owasp),
                                tags=list(tags),
                                risk_note="Dynamic imports can load arbitrary modules including malicious ones. The module name could come from user input or network data.",
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect prohibited and restricted function calls with scope extraction.

        Every finding is enriched with source code, function context,
        CWE/OWASP references, risk notes, and tags.
        """
        call_name = _get_call_name(node, self._import_aliases)
        if call_name is None:
            self.generic_visit(node)
            return

        end_line, end_col = self._get_end_pos(node)
        source = self._get_source_line(node.lineno)
        ctx = self._current_context

        # ── Helper: build enriched prohibited finding ──
        def _prohibited(
            pattern: str,
            message: str,
            *,
            risk_note: str = "",
            extra_tags: list[str] | None = None,
        ) -> Finding:
            cwe, owasp, tags = _lookup_cwe(pattern)
            all_tags = list(dict.fromkeys(list(tags) + (extra_tags or [])))  # deduplicate, preserve order
            return Finding(
                file=self.filename,
                line=node.lineno,
                col=node.col_offset,
                end_line=end_line,
                end_col=end_col,
                pattern=pattern,
                severity=FindingSeverity.PROHIBITED,
                message=message,
                source_line=source,
                function_context=ctx,
                cwe_ids=list(cwe),
                owasp_ids=list(owasp),
                tags=all_tags,
                risk_note=risk_note or message,
            )

        # ── Helper: build enriched restricted finding ──
        def _restricted(
            pattern: str,
            cap: ScopedCapability,
            message: str = "",
            *,
            risk_note: str = "",
            extra_tags: list[str] | None = None,
            confidence: str = "high",
        ) -> Finding:
            cat_val = cap.category.value
            act_val = cap.action.value
            cwe, owasp, tags = _lookup_cwe(pattern, cat_val, act_val)
            all_tags = list(dict.fromkeys(list(tags) + (extra_tags or [])))  # deduplicate, preserve order
            if not message:
                message = _get_rich_message(
                    pattern, cap.scope, cap.scope_resolved, cat_val, act_val,
                )
            if not risk_note:
                risk_note = _make_risk_note(
                    pattern, cap.scope, cap.scope_resolved, cat_val, act_val,
                )
            return Finding(
                file=self.filename,
                line=node.lineno,
                col=node.col_offset,
                end_line=end_line,
                end_col=end_col,
                pattern=pattern,
                severity=FindingSeverity.RESTRICTED,
                capability=cap,
                message=message,
                source_line=source,
                function_context=ctx,
                confidence=confidence,
                cwe_ids=list(cwe),
                owasp_ids=list(owasp),
                tags=all_tags,
                risk_note=risk_note,
            )

        # ── Check prohibited patterns ──

        # Direct prohibited calls: eval(), exec(), compile() — NOT re.compile
        if call_name in PROHIBITED_FUNCTIONS:
            self.prohibited_findings.append(
                _prohibited(
                    call_name,
                    PROHIBITED_FUNCTIONS[call_name],
                    risk_note=(
                        f"{call_name}() executes arbitrary code from strings — "
                        "the code doesn't exist in the source until runtime, "
                        "making it invisible to static analysis."
                    ),
                    extra_tags=["dynamic-exec"],
                )
            )

        # Base64/hex + exec/eval pattern
        b64_finding = _check_base64_exec_pattern(node, call_name)
        if b64_finding:
            b64_finding.file = self.filename
            b64_finding.source_line = source
            b64_finding.function_context = ctx
            b64_finding.cwe_ids = ["CWE-506"]
            b64_finding.owasp_ids = ["A03:2021"]
            b64_finding.tags = ["obfuscation", "code-injection"]
            b64_finding.risk_note = (
                "Base64/hex decoding fed into exec/eval is a classic malware "
                "obfuscation technique — the actual payload is hidden from code review."
            )
            self.prohibited_findings.append(b64_finding)

        # Dynamic importlib.import_module()
        if call_name in ("importlib.import_module",):
            if node.args:
                _, resolved = try_extract_literal(node.args[0])
                if not resolved:
                    self.prohibited_findings.append(
                        _prohibited(
                            call_name,
                            "Dynamic import with variable argument — module name determined at runtime",
                            risk_note=(
                                "The module name is a variable, not a string literal. "
                                "Any module on the system could be loaded, including "
                                "malicious ones. The target cannot be determined by static analysis."
                            ),
                            extra_tags=["dynamic-import"],
                        )
                    )

        # ctypes calls
        if "ctypes" in call_name:
            self.prohibited_findings.append(
                _prohibited(
                    call_name,
                    f"FFI/foreign function interface via {call_name} — direct memory access and native code execution",
                    risk_note=(
                        "ctypes bypasses Python's safety layer entirely. It can "
                        "read/write raw memory, call OS functions directly, and "
                        "execute native machine code — no Python-level protections apply."
                    ),
                    extra_tags=["ffi", "native-code"],
                )
            )

        # __import__ with dynamic argument
        if call_name == "__import__" and node.args:
            val, resolved = try_extract_literal(node.args[0])
            if not resolved:
                self.prohibited_findings.append(
                    _prohibited(
                        "__import__(<dynamic>)",
                        "Dynamic __import__ with variable argument — equivalent to importlib.import_module() evasion",
                        risk_note=(
                            "__import__() with a non-literal argument can load any "
                            "module at runtime. This is functionally identical to "
                            "importlib.import_module() but harder to detect."
                        ),
                        extra_tags=["dynamic-import", "evasion"],
                    )
                )

        # ── shell=True with non-literal command (PROHIBITED) ──
        if call_name in _SHELL_TRUE_CALLABLES:
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_shell_true = True
                    elif isinstance(kw.value, ast.Constant):
                        if getattr(kw.value, "value", None) is True:
                            has_shell_true = True
            if has_shell_true:
                is_dynamic = True
                if node.args:
                    _, resolved = try_extract_literal(node.args[0])
                    if resolved:
                        is_dynamic = False
                if is_dynamic:
                    self.prohibited_findings.append(
                        _prohibited(
                            f"{call_name}(shell=True)",
                            f"{call_name}() with shell=True and non-literal command — command injection vector",
                            risk_note=(
                                "shell=True passes the command through the system shell. "
                                "Combined with a dynamic (non-literal) command string, an "
                                "attacker can inject arbitrary shell commands via string manipulation."
                            ),
                            extra_tags=["shell-injection", "command-injection"],
                        )
                    )
                else:
                    scope, _ = _extract_subprocess_scope(node)
                    cap = ScopedCapability(
                        category=CapabilityCategory.SUBPROCESS,
                        action=CapabilityAction.EXEC,
                        scope=scope,
                        scope_resolved=True,
                    )
                    self.restricted_findings.append(
                        _restricted(
                            f"{call_name}(shell=True)",
                            cap,
                            f"{call_name}() with shell=True (static command: {' '.join(scope)}) — prefer shell=False with list argument",
                            risk_note=(
                                "shell=True is unnecessary when the command is a static string. "
                                "Using shell=False with a list argument is safer and avoids shell injection risks."
                            ),
                            extra_tags=["shell-true"],
                        )
                    )

        # ── Embedded REPL / debug console (PROHIBITED in production) ──
        if call_name in _REPL_CALLS:
            self.prohibited_findings.append(
                _prohibited(
                    call_name,
                    f"Embedded REPL/debug console via {call_name} — allows arbitrary code execution in production",
                    risk_note=(
                        "An interactive Python interpreter embedded in code can execute "
                        "any Python command. In a deployed skill, this is a backdoor."
                    ),
                    extra_tags=["repl", "debug-console"],
                )
            )

        # ── runpy with non-literal argument (PROHIBITED) ──
        if call_name in ("runpy.run_path", "runpy.run_module") and node.args:
            _, resolved = try_extract_literal(node.args[0])
            if not resolved:
                self.prohibited_findings.append(
                    _prohibited(
                        call_name,
                        f"{call_name}() with dynamic argument — equivalent to exec() for file/module execution",
                        risk_note=(
                            f"{call_name}() runs a Python file/module by name. With a "
                            "dynamic argument, any file on the system could be executed."
                        ),
                        extra_tags=["dynamic-exec"],
                    )
                )

        # ── sqlite3.enable_load_extension(True) (PROHIBITED) ──
        if call_name.endswith("enable_load_extension"):
            is_enabling = False
            if node.args:
                if isinstance(node.args[0], ast.Constant) and node.args[0].value is True:
                    is_enabling = True
            if is_enabling:
                self.prohibited_findings.append(
                    _prohibited(
                        "sqlite3.enable_load_extension(True)",
                        "Enabling SQLite extension loading — allows loading arbitrary shared libraries for code execution",
                        risk_note=(
                            "SQLite extension loading can load arbitrary .so/.dll files, "
                            "enabling native code execution outside Python's control."
                        ),
                        extra_tags=["sqlite", "native-code"],
                    )
                )

        # ── Introspection calls (RESTRICTED with special message) ──
        if call_name in _INTROSPECTION_CALLS:
            cap = ScopedCapability(
                category=CapabilityCategory.SYSTEM,
                action=CapabilityAction.SYSINFO,
                scope=["*"],
                scope_resolved=False,
            )
            self.restricted_findings.append(
                _restricted(
                    call_name,
                    cap,
                    f"Runtime introspection via {call_name} — can leak sensitive data from call stack or bypass sandboxes",
                    risk_note=(
                        f"{call_name} can inspect the Python runtime internals, "
                        "including local variables from calling functions (which "
                        "may contain passwords, tokens, or secrets)."
                    ),
                    extra_tags=["introspection"],
                )
            )
            self.capabilities.append(cap)

        # ── Weak randomness in security context ──
        if call_name in _WEAK_RANDOM_FUNCS:
            weak_cap = ScopedCapability(
                category=CapabilityCategory.CRYPTO,
                action=CapabilityAction.HASH,
                scope=["*"],
                scope_resolved=False,
            )
            self.restricted_findings.append(
                _restricted(
                    f"weak_random:{call_name}",
                    weak_cap,
                    f"Weak randomness via {call_name} — Mersenne Twister is predictable. Use `secrets` module for security-sensitive values.",
                    risk_note=(
                        "The random module uses Mersenne Twister, which is deterministic "
                        "and predictable. An attacker who observes 624 outputs can predict "
                        "all future values. Never use for tokens, keys, or passwords."
                    ),
                    extra_tags=["weak-random"],
                )
            )

        # ── tempfile.mktemp TOCTOU race condition ──
        if call_name == "tempfile.mktemp":
            mktemp_cap = ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.WRITE,
                scope=["*"],
                scope_resolved=False,
            )
            self.restricted_findings.append(
                _restricted(
                    "tempfile.mktemp",
                    mktemp_cap,
                    "tempfile.mktemp() is unsafe — TOCTOU race condition. Use tempfile.mkstemp() or NamedTemporaryFile instead.",
                    risk_note=(
                        "Between mktemp() generating a filename and your code creating "
                        "the file, an attacker can create a symlink at that path, "
                        "redirecting your writes to an arbitrary location."
                    ),
                    extra_tags=["toctou", "race-condition"],
                )
            )

        # ── Archive extraction (zip/tar bomb risk) ──
        if call_name in ("zipfile.ZipFile", "tarfile.open", "shutil.unpack_archive"):
            scope, resolved = _extract_first_arg_scope(node)
            cap = ScopedCapability(
                category=CapabilityCategory.FS,
                action=CapabilityAction.WRITE if "unpack" in call_name else CapabilityAction.READ,
                scope=scope,
                scope_resolved=resolved,
            )
            self.restricted_findings.append(
                _restricted(
                    call_name,
                    cap,
                    f"Archive handling via {call_name} — vulnerable to zip/tar bombs and path traversal if extracting untrusted archives.",
                    risk_note=(
                        "Archives can contain files with path traversal sequences (../) "
                        "that escape the extraction directory, or extremely compressed data "
                        "(zip bombs) that exhaust disk space. Validate contents before extracting."
                    ),
                    extra_tags=["archive"],
                )
            )
            self.capabilities.append(cap)

        # ── SSRF detection: urllib/requests with non-literal URL ──
        if call_name in ("urllib.request.urlopen", "urllib.request.Request"):
            if node.args:
                _, resolved = try_extract_literal(node.args[0])
                if not resolved:
                    ssrf_cap = ScopedCapability(
                        category=CapabilityCategory.NETWORK,
                        action=CapabilityAction.CONNECT,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    self.restricted_findings.append(
                        _restricted(
                            f"ssrf:{call_name}",
                            ssrf_cap,
                            f"Potential SSRF via {call_name} with non-literal URL — attacker-controlled URLs can access internal services.",
                            risk_note=(
                                "The URL is dynamic — an attacker could redirect this request "
                                "to internal services (169.254.169.254 for cloud metadata, "
                                "localhost services, internal APIs) to steal credentials."
                            ),
                            extra_tags=["ssrf"],
                        )
                    )

        # getattr on dangerous modules with dynamic attribute
        if call_name == "getattr" and len(node.args) >= 2:
            target = node.args[0]
            attr_arg = node.args[1]
            if isinstance(target, ast.Name):
                target_root = self._import_aliases.get(target.id, target.id).split(".")[0]
            else:
                target_root = ""
            if target_root in DANGEROUS_GETATTR_MODULES:
                _, resolved = try_extract_literal(attr_arg)
                if not resolved:
                    self.prohibited_findings.append(
                        _prohibited(
                            f"getattr({target_root}, <dynamic>)",
                            f"Dynamic attribute access on {target_root} — can invoke any function at runtime, bypassing static analysis",
                            risk_note=(
                                f"getattr({target_root}, variable) can access any attribute "
                                f"on the {target_root} module at runtime, including dangerous "
                                "functions like system(), popen(), etc. This defeats static analysis."
                            ),
                            extra_tags=["dynamic-access", "evasion"],
                        )
                    )

        # ── Check restricted patterns with scope extraction ──
        if self._sink_input_is_tainted(
            node,
            positional_indices=(0,),
            keyword_names=("args", "cmd", "command"),
        ):
            # Tainted input reaching command execution sink.
            if call_name in _TAINT_COMMAND_SINKS:
                cap = ScopedCapability(
                    category=CapabilityCategory.SUBPROCESS,
                    action=CapabilityAction.EXEC,
                    scope=["*"],
                    scope_resolved=False,
                )
                self.restricted_findings.append(
                    _restricted(
                        f"taint:{call_name}",
                        cap,
                        f"User-controlled input reaches command execution ({call_name}).",
                        risk_note=(
                            "Data from a user or request is being used to build/run a command. "
                            "Validate against an allowlist and prefer fixed argument arrays."
                        ),
                        extra_tags=["taint-flow", "source-to-sink", "command-injection"],
                        confidence="high",
                    )
                )

            # Tainted input reaching URL/network sink.
            if call_name in _TAINT_URL_SINKS:
                cap = ScopedCapability(
                    category=CapabilityCategory.NETWORK,
                    action=CapabilityAction.CONNECT,
                    scope=["*"],
                    scope_resolved=False,
                )
                self.restricted_findings.append(
                    _restricted(
                        f"taint:{call_name}",
                        cap,
                        f"User-controlled input reaches outbound request target ({call_name}).",
                        risk_note=(
                            "A user-controlled URL can redirect this request to internal services or "
                            "attacker endpoints (SSRF/data exfiltration risk)."
                        ),
                        extra_tags=["taint-flow", "source-to-sink", "ssrf"],
                        confidence="high",
                    )
                )

            # Tainted input reaching file path sink.
            if call_name in _TAINT_PATH_SINKS:
                action = CapabilityAction.READ if call_name != "open" else _detect_open_mode(node)
                cap = ScopedCapability(
                    category=CapabilityCategory.FS,
                    action=action,
                    scope=["*"],
                    scope_resolved=False,
                )
                self.restricted_findings.append(
                    _restricted(
                        f"taint:{call_name}",
                        cap,
                        f"User-controlled input reaches filesystem path operation ({call_name}).",
                        risk_note=(
                            "A user-controlled path can access or modify unintended files. "
                            "Use canonicalization and enforce a fixed base-directory allowlist."
                        ),
                        extra_tags=["taint-flow", "source-to-sink", "path-traversal"],
                        confidence="high",
                    )
                )

        # URL sinks may accept URL as second positional arg (e.g., requests.request(method, url)).
        if call_name in _TAINT_URL_SINKS and self._sink_input_is_tainted(
            node,
            positional_indices=(1,),
            keyword_names=("url", "uri", "endpoint"),
        ):
            cap = ScopedCapability(
                category=CapabilityCategory.NETWORK,
                action=CapabilityAction.CONNECT,
                scope=["*"],
                scope_resolved=False,
            )
            self.restricted_findings.append(
                _restricted(
                    f"taint:{call_name}",
                    cap,
                    f"User-controlled input reaches outbound request target ({call_name}).",
                    risk_note=(
                        "A user-controlled URL can redirect this request to internal services or "
                        "attacker endpoints (SSRF/data exfiltration risk)."
                    ),
                    extra_tags=["taint-flow", "source-to-sink", "ssrf"],
                    confidence="high",
                )
            )

        # Path sinks may use src/dst or path-like keyword arguments.
        if call_name in _TAINT_PATH_SINKS and self._sink_input_is_tainted(
            node,
            positional_indices=(1,),
            keyword_names=("path", "file", "filename", "src", "dst"),
        ):
            action = CapabilityAction.READ if call_name != "open" else _detect_open_mode(node)
            cap = ScopedCapability(
                category=CapabilityCategory.FS,
                action=action,
                scope=["*"],
                scope_resolved=False,
            )
            self.restricted_findings.append(
                _restricted(
                    f"taint:{call_name}",
                    cap,
                    f"User-controlled input reaches filesystem path operation ({call_name}).",
                    risk_note=(
                        "A user-controlled path can access or modify unintended files. "
                        "Use canonicalization and enforce a fixed base-directory allowlist."
                    ),
                    extra_tags=["taint-flow", "source-to-sink", "path-traversal"],
                    confidence="high",
                )
            )

        # SQL execute-style sinks (cursor.execute / executemany) with tainted query.
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
            if self._sink_input_is_tainted(
                node,
                positional_indices=(0,),
                keyword_names=("query", "sql", "statement"),
            ):
                cap = ScopedCapability(
                    category=CapabilityCategory.NETWORK,
                    action=CapabilityAction.CONNECT,
                    scope=["*"],
                    scope_resolved=False,
                )
                self.restricted_findings.append(
                    _restricted(
                        "taint:sql.execute",
                        cap,
                        "User-controlled input reaches SQL execution.",
                        risk_note=(
                            "Data from a user or request is being executed as SQL. "
                            "Use parameterized queries and keep SQL structure separate from user data."
                        ),
                        extra_tags=["taint-flow", "source-to-sink", "sql-injection"],
                        confidence="high",
                    )
                )

        # YAML loading: only flag yaml.load* when loader is missing/unsafe.
        if call_name in ("yaml.load", "yaml.load_all"):
            scope, resolved = _extract_first_arg_scope(node)
            cap = ScopedCapability(
                category=CapabilityCategory.SERIAL,
                action=CapabilityAction.DESERIALIZE,
                scope=scope,
                scope_resolved=resolved,
            )
            self.capabilities.append(cap)

            loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
            if loader_kw and _is_safe_yaml_loader_expr(loader_kw.value):
                self.generic_visit(node)
                return

            msg = (
                f"{call_name}() without a safe loader — untrusted YAML may construct arbitrary Python objects. "
                "Use yaml.safe_load()/safe_load_all() or Loader=yaml.SafeLoader."
            )
            self.restricted_findings.append(
                _restricted(
                    call_name,
                    cap,
                    msg,
                    risk_note=(
                        "PyYAML's generic loaders can deserialize attacker-controlled tags into Python objects. "
                        "Only SafeLoader/CSafeLoader should be used for untrusted input."
                    ),
                    extra_tags=["unsafe-loader", "yaml"],
                )
            )
            self.generic_visit(node)
            return

        # Special handling for open() — detect read vs write mode
        if call_name == "open":
            action = _detect_open_mode(node)
            scope, resolved = _extract_first_arg_scope(node)
            cap = ScopedCapability(
                category=CapabilityCategory.FS,
                action=action,
                scope=scope,
                scope_resolved=resolved,
            )
            msg = _get_rich_message("open", scope, resolved, "fs", action.value)
            if not msg or msg == "open":
                target = _format_target(scope, resolved)
                msg = f"File {action.value}{target}" if target else f"File {action.value} operation"
                if not resolved:
                    msg += " (target path unresolved)"
            self.restricted_findings.append(
                _restricted(call_name, cap, msg, extra_tags=["file-io"])
            )
            self.capabilities.append(cap)

        # Subprocess calls — extract binary name
        elif call_name in _SUBPROCESS_SPECIAL_CASES and call_name != "open":
            scope, resolved = _extract_subprocess_scope(node)
            cap = ScopedCapability(
                category=CapabilityCategory.SUBPROCESS,
                action=CapabilityAction.EXEC,
                scope=scope,
                scope_resolved=resolved,
            )
            self.restricted_findings.append(_restricted(call_name, cap))
            self.capabilities.append(cap)

        # All other restricted calls — extract scope from first arg
        elif call_name in RESTRICTED_CALL_PATTERNS and call_name not in _SUBPROCESS_SPECIAL_CASES:
            cat, action = RESTRICTED_CALL_PATTERNS[call_name]
            scope, resolved = _extract_first_arg_scope(node)
            cap = ScopedCapability(
                category=cat,
                action=action,
                scope=scope,
                scope_resolved=resolved,
            )
            self.restricted_findings.append(_restricted(call_name, cap))
            self.capabilities.append(cap)

        # pathlib.Path operations (read + write + delete)
        if "pathlib" in call_name or "Path" in call_name:
            _pathlib_write_ops = ("write_text", "write_bytes", "mkdir", "touch", "rename", "replace", "symlink_to", "hardlink_to")
            _pathlib_read_ops = ("read_text", "read_bytes", "open", "stat", "exists", "is_file", "is_dir", "glob", "rglob", "iterdir", "resolve")
            _pathlib_delete_ops = ("unlink", "rmdir")
            if any(w in call_name for w in _pathlib_write_ops):
                scope, resolved = _extract_first_arg_scope(node)
                cap = ScopedCapability(
                    category=CapabilityCategory.FS,
                    action=CapabilityAction.WRITE,
                    scope=scope,
                    scope_resolved=resolved,
                )
                self.restricted_findings.append(
                    _restricted(call_name, cap, f"Filesystem write via {call_name}", extra_tags=["pathlib"])
                )
                self.capabilities.append(cap)
            elif any(r in call_name for r in _pathlib_read_ops):
                scope, resolved = _extract_first_arg_scope(node)
                cap = ScopedCapability(
                    category=CapabilityCategory.FS,
                    action=CapabilityAction.READ,
                    scope=scope,
                    scope_resolved=resolved,
                )
                self.restricted_findings.append(
                    _restricted(call_name, cap, f"Filesystem read via {call_name}", extra_tags=["pathlib"])
                )
                self.capabilities.append(cap)
            elif any(d in call_name for d in _pathlib_delete_ops):
                scope, resolved = _extract_first_arg_scope(node)
                cap = ScopedCapability(
                    category=CapabilityCategory.FS,
                    action=CapabilityAction.DELETE,
                    scope=scope,
                    scope_resolved=resolved,
                )
                self.restricted_findings.append(
                    _restricted(call_name, cap, f"Filesystem delete via {call_name}", extra_tags=["pathlib"])
                )
                self.capabilities.append(cap)

        # shutil operations
        if call_name.startswith("shutil."):
            action = CapabilityAction.WRITE
            if "remove" in call_name or "rmtree" in call_name:
                action = CapabilityAction.DELETE
            scope, resolved = _extract_first_arg_scope(node)
            cap = ScopedCapability(
                category=CapabilityCategory.FS,
                action=action,
                scope=scope,
                scope_resolved=resolved,
            )
            self.restricted_findings.append(
                _restricted(call_name, cap, extra_tags=["shutil"])
            )
            self.capabilities.append(cap)

        self.generic_visit(node)


    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect weak random assignments to security-sensitive variables."""
        if self._expr_is_tainted(node.value):
            for target in node.targets:
                self._mark_tainted_target(target)

        if isinstance(node.value, ast.Call):
            call_name = _get_call_name(node.value)
            if call_name and call_name in _WEAK_RANDOM_FUNCS:
                for target in node.targets:
                    var_name = ""
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                    elif isinstance(target, ast.Attribute):
                        var_name = target.attr.lower()

                    if any(sec in var_name for sec in _SECURITY_CONTEXT_NAMES):
                        end_line, end_col = self._get_end_pos(node)
                        source = self._get_source_line(node.lineno)
                        cwe, owasp, tags = _lookup_cwe(call_name)
                        self.prohibited_findings.append(
                            Finding(
                                file=self.filename,
                                line=node.lineno,
                                col=node.col_offset,
                                end_line=end_line,
                                end_col=end_col,
                                pattern=f"weak_random_secret:{call_name}",
                                severity=FindingSeverity.PROHIBITED,
                                message=(
                                    f"Weak randomness ({call_name}) assigned to "
                                    f"security-sensitive variable '{var_name}' — "
                                    "use `secrets` module instead."
                                ),
                                source_line=source,
                                function_context=self._current_context,
                                cwe_ids=["CWE-330"],
                                owasp_ids=["A02:2021"],
                                tags=["weak-random", "credential-generation"],
                                risk_note=(
                                    f"'{var_name}' appears to hold a security-sensitive value, "
                                    f"but it's generated by {call_name} (Mersenne Twister). "
                                    "An attacker can predict all values after observing ~624 outputs."
                                ),
                            )
                        )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        """Mark functions that return tainted data (lightweight interprocedural taint)."""
        if node.value is not None and self._function_name_stack and self._expr_is_tainted(node.value):
            self._tainted_return_functions.add(self._function_name_stack[-1])
        self.generic_visit(node)


def parse_file(
    file_path: Path,
    relative_name: str,
) -> tuple[list[Finding], list[Finding], list[ScopedCapability], list[Finding]]:
    """Parse a single Python file and extract findings.

    Returns:
        (prohibited_findings, restricted_findings, capabilities, context_findings)

    context_findings are suppressed import-level findings — they feed the
    capability map but should NOT be counted in the report card's finding
    count or displayed in the findings table.

    Every finding is enriched with:
    - source_line: the actual code text at the finding location
    - function_context: enclosing function/class (e.g., "MyClass.deploy()")
    - cwe_ids / owasp_ids: industry-standard vulnerability references
    - risk_note: human-readable "why this matters here" explanation
    - tags: categorization labels for filtering
    - end_line / end_col: AST node range for agent code modification
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return [], [], [], []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        logger.warning("Syntax error in %s: %s", file_path, e)
        return [], [], [], []

    # Split source into lines for enrichment
    source_lines = source.splitlines()

    visitor = AegisASTVisitor(relative_name, source_lines=source_lines)
    visitor.visit(tree)

    return (
        visitor.prohibited_findings,
        visitor.restricted_findings,
        visitor.capabilities,
        visitor.context_findings,
    )
