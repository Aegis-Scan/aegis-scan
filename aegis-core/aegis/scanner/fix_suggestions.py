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

"""Auto-fix suggestions for Aegis findings.

Maps detected patterns to actionable remediation advice. Every Finding
and CombinationRisk gets a suggested_fix populated before the report
is generated.
"""

from __future__ import annotations

from aegis.models.capabilities import CombinationRisk, Finding


# ── Pattern → Fix mapping ──
# Keys are matched via substring against the Finding.pattern field.
# Order matters: first match wins, so more specific patterns go first.

PATTERN_FIXES: list[tuple[str, str]] = [
    # Python restricted — subprocess (BEFORE generic exec/eval to avoid false matches)
    ("subprocess.call", "Use `subprocess.run()` with a list argument and `shell=False` for safer command execution."),
    ("subprocess.run", "Ensure `subprocess.run()` uses a list argument (not a string) and `shell=False`. Pin commands to specific, audited executables."),
    ("subprocess.Popen", "Use `subprocess.run()` with `shell=False` and a list argument. If Popen is required, avoid `shell=True` and validate all arguments."),
    ("subprocess.check_output", "Use `subprocess.run(capture_output=True)` with `shell=False` and a list argument instead."),
    ("subprocess.check_call", "Use `subprocess.run(check=True)` with `shell=False` and a list argument instead."),
    ("os.system", "Replace `os.system()` with `subprocess.run()` using a list argument and `shell=False`."),
    ("os.popen", "Replace `os.popen()` with `subprocess.run(capture_output=True)` using `shell=False`."),

    # JS/TS — subprocess (BEFORE generic exec/eval)
    ("child_process", "Use `child_process.execFile()` or `spawn()` with `shell: false`. Validate all arguments and pin to specific executables."),
    ("shelljs", "Replace shelljs with `child_process.execFile()` or `spawn()` with `shell: false` for safer command execution."),

    # Python restricted — serialization
    ("pickle.load", "Replace `pickle.load()` with `json.load()` or another safe serialization format. Pickle can execute arbitrary code during deserialization."),
    ("pickle.loads", "Replace `pickle.loads()` with `json.loads()` or another safe serialization format. Pickle can execute arbitrary code during deserialization."),
    ("marshal.load", "Replace `marshal.load()` with `json.load()` or another safe format. Marshal is not secure against malicious data."),
    ("yaml.load", "Use `yaml.safe_load()` instead of `yaml.load()`. The unsafe loader can execute arbitrary Python code embedded in YAML."),

    # shell=True patterns (BEFORE generic subprocess matches)
    ("shell=true", "Remove `shell=True`. Use a list argument with `shell=False` (the default). If shell features are needed, use `shlex.split()` on static commands."),

    # Python prohibited (after more specific matches)
    ("eval", "Remove dynamic code execution. Use `ast.literal_eval()` for safe data parsing, or refactor to avoid evaluating arbitrary strings."),
    ("exec", "Remove `exec()`. Refactor to use explicit function calls or configuration-driven logic instead of executing code from strings."),
    ("compile", "Remove `compile()`. Use `ast.literal_eval()` for data parsing or refactor to avoid building code objects from strings."),
    ("importlib", "Replace dynamic imports with explicit `import` statements. If dynamic loading is required, validate module names against a strict allowlist."),
    ("ctypes", "Remove ctypes usage. Use pure-Python alternatives or well-audited C extension modules instead of direct memory access."),
    ("base64_exec", "Remove base64-decoded code execution. This is a code obfuscation technique — refactor to use plain source code."),

    # Legacy / low-level execution sinks (from PDF research)
    ("platform.popen", "Replace `platform.popen()` with `subprocess.run()` using `shell=False`. `platform.popen` is a deprecated wrapper around `os.popen`."),
    ("posix.system", "Replace `posix.system()` with `subprocess.run()` using `shell=False`. Direct `posix` module usage bypasses the `os` module abstraction."),
    ("posix.popen", "Replace `posix.popen()` with `subprocess.run(capture_output=True)` using `shell=False`."),
    ("pty.spawn", "Remove `pty.spawn()`. Pseudo-terminal spawning is a common reverse shell technique. Use `subprocess.run()` if process execution is needed."),
    ("commands", "Remove `commands` module usage (Python 2 legacy). Use `subprocess.run()` with `shell=False` instead."),

    # Metaprogramming / introspection (from PDF research)
    ("runpy.run_path", "Replace `runpy.run_path()` with explicit imports. If dynamic module loading is needed, validate paths against a strict allowlist."),
    ("runpy.run_module", "Replace `runpy.run_module()` with explicit imports. If dynamic module loading is needed, validate module names against a strict allowlist."),
    ("code.interactive", "Remove embedded REPL/debug console. Interactive interpreters allow arbitrary code execution in production."),
    ("codeop", "Remove `codeop` usage. The command compiler is intended for REPL construction and should not appear in production code."),
    ("sys._getframe", "Remove `sys._getframe()`. Frame inspection can leak sensitive data from the call stack. Use explicit parameter passing instead."),
    ("sys.settrace", "Remove `sys.settrace()`. Global trace functions see every line of code executed and can be abused to intercept sensitive operations."),
    ("sys.setprofile", "Remove `sys.setprofile()`. Global profile functions can intercept all function calls and leak sensitive data."),
    ("inspect.currentframe", "Remove `inspect.currentframe()`. Frame inspection can leak local variables including passwords and secrets."),

    # Evasion / privilege / memory (hardening additions)
    ("mmap.mmap", "Remove `mmap.mmap()`. Memory-mapped file I/O bypasses normal file APIs and access controls. Use standard file operations instead."),
    ("cffi.FFI", "Remove `cffi.FFI()`. Foreign function interfaces allow direct C library access and memory corruption. Use pure-Python alternatives."),
    ("os.setuid", "Remove `os.setuid()`. Privilege manipulation should not occur in application code — use system-level process managers."),
    ("os.setgid", "Remove `os.setgid()`. Privilege manipulation should not occur in application code — use system-level process managers."),
    ("os.chroot", "Remove `os.chroot()`. Chroot jails are easily escaped — use proper container isolation (Docker, namespaces) instead."),
    ("os.pipe", "Review `os.pipe()` usage. File descriptor manipulation can redirect I/O streams. Prefer `subprocess.PIPE` or high-level IPC."),
    ("os.dup", "Review `os.dup()`/`os.dup2()` usage. File descriptor duplication can redirect stdin/stdout/stderr silently."),
    ("sys.path.insert", "Remove `sys.path.insert()`. Module search path manipulation enables malicious module loading. Use proper package installation instead."),
    ("sys.path.append", "Remove `sys.path.append()`. Module search path manipulation enables malicious module loading. Use proper package installation instead."),
    ("types.CodeType", "Remove `types.CodeType()`. Code object construction allows arbitrary code execution without calling eval/exec. Refactor to explicit functions."),
    ("types.FunctionType", "Remove `types.FunctionType()`. Function construction from code objects enables indirect code execution. Use normal function definitions."),
    ("importlib.util.spec_from_file_location", "Replace `importlib.util.spec_from_file_location()` with explicit imports. Validate file paths against a strict allowlist if dynamic loading is required."),
    ("importlib.reload", "Remove `importlib.reload()`. Module reloading can replace module contents at runtime — use process restart instead."),
    ("inspect.stack", "Remove `inspect.stack()`. Stack inspection can leak local variables from calling functions including sensitive data."),
    ("gc.get_objects", "Remove `gc.get_objects()`. It exposes references to all tracked objects including database connections, credentials, and other sensitive data."),
    ("gc.get_referrers", "Remove `gc.get_referrers()`. It can be used to traverse object graphs and reach sensitive objects not explicitly shared."),

    # sqlite3 special sinks (from PDF research)
    ("enable_load_extension", "Remove `enable_load_extension(True)`. SQLite extension loading allows execution of arbitrary shared libraries (DLLs/SOs)."),

    # multiprocessing deserialization (from PDF research)
    ("multiprocessing.connection", "Avoid exposing multiprocessing Listeners to the network. `recv()` automatically unpickles data — malicious payloads cause RCE."),
    ("multiprocessing.pipe", "Ensure multiprocessing Pipe connections are not accessible to untrusted code. Data is pickle-serialized automatically."),

    # Python restricted — network
    ("requests.get", "Ensure `verify=True` (the default) for SSL certificate verification. Pin URLs to known-good endpoints."),
    ("requests.post", "Ensure `verify=True` for SSL verification. Validate all data before sending."),
    ("verify=False", "Remove `verify=False` to enable SSL certificate verification. Disabling SSL verification exposes the connection to man-in-the-middle attacks."),
    ("httpx", "Ensure SSL verification is enabled. Pin URLs to known-good endpoints."),

    # Python restricted — filesystem
    ("open", "Use the minimum required file permissions. Prefer project-local or temp directories. Validate file paths against an allowlist."),
    ("shutil", "Validate source and destination paths. Prefer project-local directories and avoid operations on sensitive system paths."),
    ("pathlib", "Validate that Path objects point to expected project-local directories, not sensitive system paths like ~/.ssh or /etc."),

    # Hardcoded secrets
    ("hardcoded_secret", "Move secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault, or `python-dotenv` with `.env` files in `.gitignore`)."),
    ("hardcoded_key", "Move this API key to an environment variable or secrets manager. Rotate the key immediately — it may have been exposed in version control."),
    ("connection_string", "Move database credentials to environment variables. Use `DATABASE_URL` from env instead of hardcoding connection strings with embedded passwords."),
    ("high_entropy_string", "If this is a secret, move it to an environment variable or secrets manager. If it's not a secret, consider adding a comment explaining what it is."),

    # Weak randomness (from PDF research)
    ("weak_random_secret", "Replace `random` module with the `secrets` module for generating security-sensitive values (tokens, keys, passwords, session IDs)."),
    ("weak_random", "The `random` module uses Mersenne Twister (predictable). Use `secrets.token_hex()`, `secrets.token_urlsafe()`, or `secrets.choice()` for security-sensitive values."),

    # tempfile.mktemp TOCTOU (from PDF research)
    ("tempfile.mktemp", "Replace `tempfile.mktemp()` with `tempfile.mkstemp()` or `NamedTemporaryFile`. `mktemp()` has a TOCTOU race condition — an attacker can create a symlink between name generation and file creation."),

    # Archive bomb risk (from PDF research)
    ("zipfile", "Validate archive contents before extraction. Check file sizes, total extracted size, and paths to prevent zip bombs and path traversal attacks. Use `ZipFile.infolist()` to inspect before extracting."),
    ("tarfile", "Validate archive contents before extraction. Use `tarfile.data_filter` (Python 3.12+) or manually check members for path traversal (`../`) and absolute paths. Never extract with `extractall()` on untrusted archives."),
    ("shutil.unpack_archive", "Validate the archive before unpacking. `shutil.unpack_archive()` provides no protection against zip/tar bombs or path traversal. Consider using `zipfile`/`tarfile` with explicit member validation."),

    # SSRF (from PDF research)
    ("ssrf:", "Validate and restrict URLs to an allowlist of permitted hosts/schemes. Block `file://`, `ftp://`, and internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use `urllib.parse` to validate scheme and host."),

    # Module shadowing (from PDF research)
    ("shadow_module", "Rename this file/package to avoid shadowing the Python standard library module. Shadowing breaks `import` resolution and can introduce subtle security vulnerabilities."),

    # High complexity (from PDF research)
    ("high_complexity", "Refactor this function to reduce cyclomatic complexity. Break into smaller functions, simplify conditional logic, and use early returns. High-complexity functions are more likely to contain subtle security bugs."),

    # XML / XXE (from PDF research, extending existing)
    ("xml.etree", "Consider using `defusedxml.ElementTree` instead. The standard `xml.etree` is vulnerable to Billion Laughs (entity expansion DoS). See: https://pypi.org/project/defusedxml/"),
    ("xml.dom", "Replace with `defusedxml` variants. Standard XML DOM parsers are vulnerable to XXE and entity expansion attacks."),
    ("xml.sax", "Replace with `defusedxml.sax`. The standard `xml.sax` parser does not prevent external entity resolution by default."),
    ("plistlib", "Validate plist input before parsing. Older Python versions (< 3.9.1) are vulnerable to XXE in plistlib. Binary plist parsing is vulnerable to memory exhaustion."),

    # Cleartext protocols (from PDF research)
    ("telnetlib", "Replace Telnet with SSH. Telnet transmits all data including credentials in cleartext. Use `paramiko` or `asyncssh` for secure remote access."),
    ("ftplib.ftp", "Replace FTP with SFTP or FTPS (`ftplib.FTP_TLS`). Standard FTP transmits credentials in cleartext."),

    # Sensitive path access
    ("~/.ssh", "Write to a project-local or temp directory instead. If SSH access is required, use ssh-agent or a credential helper rather than reading key files directly."),
    ("~/.aws", "Use AWS credential chain (env vars → config file → IAM role) instead of reading credential files directly."),
    ("~/.bashrc", "Write to a project-local or temp directory instead of modifying shell startup files."),
    ("~/.zshrc", "Write to a project-local or temp directory instead of modifying shell startup files."),
    ("~/.gitconfig", "Use `git config --local` instead of modifying the global Git configuration."),
    ("/etc", "Avoid writing to system configuration directories. Use project-local config files instead."),

    # JS/TS prohibited
    ("\\beval\\s*\\(", "Remove `eval()`. Use `JSON.parse()` for data parsing, or refactor to use explicit function calls."),
    ("new\\s+Function", "Remove `new Function()`. Refactor to use explicit function definitions or `JSON.parse()` for data."),
    ("vm.runIn", "Use a proper sandboxing solution (e.g., `vm2` or isolated-vm) instead of the built-in `vm` module, which is not a security mechanism."),

    # JS/TS restricted
    ("child_process", "Use `child_process.execFile()` or `spawn()` with `shell: false`. Validate all arguments and pin to specific executables."),
    ("shelljs", "Replace shelljs with `child_process.execFile()` or `spawn()` with `shell: false` for safer command execution."),
    ("process.env", "Document which environment variables are required. Consider using a config validation library (e.g., `envalid`, `joi`) to validate env vars at startup."),
    ("dotenv", "Ensure `.env` files are in `.gitignore`. Document required variables in a `.env.example` file."),
    ("puppeteer", "If browser automation is required, use headless mode and restrict navigation to known-good URLs. Add timeouts and error handling."),
    ("playwright", "If browser automation is required, restrict navigation to known-good URLs. Use context isolation and add timeouts."),

    # General capabilities
    ("keyring", "Document which keychain entries are accessed and why. Request minimum necessary permissions."),
    ("crypto", "Document which cryptographic operations are performed and why. Use well-established algorithms and key sizes."),
    ("import requests", "Pin URLs to known-good endpoints. Ensure SSL verification is enabled (default)."),
]


# ── Combination risk → Fix mapping ──

COMBINATION_FIXES: dict[str, str] = {
    "automated-purchasing": (
        "Split browser automation and credential access into separate skills with separate approval flows. "
        "Require explicit user confirmation before any financial transaction. Add purchase amount limits and "
        "domain allowlists."
    ),
    "rce-pipeline": (
        "Remove the download-write-execute chain. If external tools are needed, vendor them in the repository "
        "and verify checksums. Never download and execute code at runtime."
    ),
    "data-exfiltration": (
        "Restrict network access to specific, documented endpoints. Restrict file read access to project-local "
        "directories. Add network egress monitoring or use a proxy that logs all outbound requests."
    ),
    "secret-exfiltration": (
        "Minimize credential scope — request only the specific secrets needed. Restrict network access to "
        "documented endpoints. Use short-lived tokens instead of long-lived secrets where possible."
    ),
    "credential-harvesting": (
        "Audit every environment variable and secret read. Restrict network access to specific endpoints. "
        "Use least-privilege credential access — don't read all env vars when you only need one."
    ),
    "crypto-ransomware": (
        "If encryption is legitimate, ensure the key is user-controlled and the process is transparent. "
        "Never encrypt files in-place without explicit user consent and backup verification."
    ),
    "persistence-mechanism": (
        "Remove signal handler installation unless absolutely necessary. Avoid writing to startup directories. "
        "Document why persistence is needed and provide an uninstall mechanism."
    ),
    "browser-credential-theft": (
        "Separate browser automation from credential access. If both are needed, use OAuth flows with "
        "minimum scopes instead of reading stored credentials directly."
    ),
    "deserialization-rce": (
        "Use safe serialization formats (JSON) instead of pickle/marshal for network data. "
        "If deserialization is required, validate and sanitize all input before deserializing."
    ),
    "supply-chain-autoload": (
        "Pin all external binaries to specific versions and verify checksums. Add unrecognized binaries "
        "to the allow-list after review, or replace them with known alternatives."
    ),
    "network-listen-exec": (
        "Restrict the network listener to localhost only. Validate and sanitize all incoming data before "
        "using it in subprocess commands. Use an allowlist for permitted commands."
    ),
}


def get_fix_for_finding(finding: Finding) -> str | None:
    """Get a fix suggestion for a finding based on its pattern.

    Returns the fix suggestion string, or None if no match.
    """
    pattern = finding.pattern.lower()
    message = finding.message.lower()

    for match_str, fix in PATTERN_FIXES:
        match_lower = match_str.lower()
        if match_lower in pattern or match_lower in message:
            return fix

    # Fallback: generate a generic suggestion based on capability
    if finding.capability:
        cap = finding.capability
        if cap.category.value == "fs" and cap.action.value == "write":
            return "Write to a project-local or temp directory instead of sensitive system paths."
        elif cap.category.value == "network":
            return "Pin network access to specific, documented endpoints. Ensure SSL verification is enabled."
        elif cap.category.value == "subprocess":
            return "Pin subprocess commands to specific, audited executables. Avoid shell=True and validate all arguments."
        elif cap.category.value == "secret":
            return "Minimize credential scope. Document which secrets are needed and why."
        elif cap.category.value == "browser":
            return "Restrict browser navigation to known-good URLs. Use headless mode and add timeouts."

    return None


def get_fix_for_combination(risk: CombinationRisk) -> str | None:
    """Get a fix suggestion for a combination risk based on its rule_id.

    Returns the fix suggestion string, or None if no match.
    """
    return COMBINATION_FIXES.get(risk.rule_id)


def populate_fix_suggestions(
    findings: list[Finding],
    combination_risks: list[CombinationRisk],
) -> None:
    """Populate suggested_fix on all findings and combination risks.

    Modifies the objects in-place.
    """
    for finding in findings:
        if finding.suggested_fix is None:
            finding.suggested_fix = get_fix_for_finding(finding)

    for risk in combination_risks:
        if risk.suggested_fix is None:
            risk.suggested_fix = get_fix_for_combination(risk)
