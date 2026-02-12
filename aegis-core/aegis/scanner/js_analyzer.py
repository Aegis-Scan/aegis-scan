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

"""JavaScript/TypeScript analyzer — regex-based capability extraction.

Parses .js, .ts, .mjs, .cjs, .jsx, .tsx files using regex + heuristic
pattern matching (similar to shell_analyzer.py — no tree-sitter dependency).

Detects the same capability categories as the Python AST parser:
- Network, Filesystem, Subprocess, Browser, Secrets, Crypto,
  Deserialization, Prohibited patterns, Hardcoded secrets
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from aegis.models.capabilities import (
    CapabilityAction,
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)

logger = logging.getLogger(__name__)


# ── Prohibited patterns ──

PROHIBITED_JS_PATTERNS: list[tuple[re.Pattern, str]] = [
    # eval()
    (
        re.compile(r"""\beval\s*\("""),
        "Dynamic code execution via eval() — arbitrary code execution",
    ),
    # new Function()
    (
        re.compile(r"""\bnew\s+Function\s*\("""),
        "Dynamic code execution via new Function() — arbitrary code execution",
    ),
    # child_process.exec with template literal or concatenation
    (
        re.compile(r"""child_process\s*[\.\[\]'"]+\s*exec\s*\(\s*`"""),
        "child_process.exec with template literal — potential command injection",
    ),
    (
        re.compile(r"""\.exec\s*\(\s*[a-zA-Z_]\w*\s*\+"""),
        "exec() with string concatenation — potential command injection",
    ),
    # vm.runInContext / vm.runInNewContext
    (
        re.compile(r"""\bvm\s*\.\s*runIn(New)?Context\s*\("""),
        "Dynamic code execution via vm.runInContext — sandbox escape risk",
    ),
    # require() with dynamic/variable argument
    (
        re.compile(r"""\brequire\s*\(\s*[a-zA-Z_]\w*\s*[\+\)]"""),
        "Dynamic require() — module loading from variable (potential code injection)",
    ),
]


# ── Network patterns ──

NETWORK_JS_PATTERNS: list[tuple[re.Pattern, str, str | None]] = [
    # fetch()
    (re.compile(r"""\bfetch\s*\("""), "fetch", None),
    # axios
    (re.compile(r"""\baxios\s*\.\s*(get|post|put|patch|delete|request|head|options)\s*\("""), "axios", None),
    (re.compile(r"""\baxios\s*\("""), "axios", None),
    # http/https
    (re.compile(r"""\bhttps?\s*\.\s*(request|get|createServer)\s*\("""), "http/https", None),
    # net.connect
    (re.compile(r"""\bnet\s*\.\s*(connect|createConnection|createServer)\s*\("""), "net", None),
    # WebSocket
    (re.compile(r"""\bnew\s+WebSocket\s*\("""), "WebSocket", None),
    # XMLHttpRequest
    (re.compile(r"""\bnew\s+XMLHttpRequest\b"""), "XMLHttpRequest", None),
    (re.compile(r"""\bXMLHttpRequest\s*\("""), "XMLHttpRequest", None),
    # node-fetch
    (re.compile(r"""require\s*\(\s*['"]node-fetch['"]\s*\)"""), "node-fetch", None),
    # got
    (re.compile(r"""require\s*\(\s*['"]got['"]\s*\)"""), "got", None),
    (re.compile(r"""\bgot\s*\.\s*(get|post|put|patch|delete|head)\s*\("""), "got", None),
    # superagent
    (re.compile(r"""require\s*\(\s*['"]superagent['"]\s*\)"""), "superagent", None),
    # Database clients
    (re.compile(r"""require\s*\(\s*['"]pg['"]\s*\)"""), "pg (PostgreSQL)", None),
    (re.compile(r"""\bnew\s+Pool\s*\("""), "pg.Pool", None),
    (re.compile(r"""\bnew\s+Client\s*\("""), "pg/db Client", None),
    (re.compile(r"""require\s*\(\s*['"]mysql2?['"]\s*\)"""), "mysql", None),
    (re.compile(r"""require\s*\(\s*['"]mongodb['"]\s*\)"""), "mongodb", None),
    (re.compile(r"""\bMongoClient\s*\.\s*connect\s*\("""), "MongoClient", None),
    (re.compile(r"""require\s*\(\s*['"]redis['"]\s*\)"""), "redis", None),
    (re.compile(r"""require\s*\(\s*['"]mongoose['"]\s*\)"""), "mongoose", None),
    (re.compile(r"""\bmongoose\s*\.\s*connect\s*\("""), "mongoose.connect", None),
    (re.compile(r"""require\s*\(\s*['"]sequelize['"]\s*\)"""), "sequelize", None),
    (re.compile(r"""\bnew\s+Sequelize\s*\("""), "Sequelize", None),
    (re.compile(r"""require\s*\(\s*['"]knex['"]\s*\)"""), "knex", None),
    (re.compile(r"""from\s+['"]@prisma\/client['"]"""), "prisma", None),
    (re.compile(r"""\bnew\s+PrismaClient\s*\("""), "PrismaClient", None),
    # import statements
    (re.compile(r"""from\s+['"]axios['"]"""), "axios (import)", None),
    (re.compile(r"""from\s+['"]node-fetch['"]"""), "node-fetch (import)", None),
    (re.compile(r"""from\s+['"]got['"]"""), "got (import)", None),
]


# ── Filesystem patterns ──

FS_JS_PATTERNS: list[tuple[re.Pattern, str, CapabilityAction]] = [
    # fs read
    (re.compile(r"""\bfs\s*\.\s*(readFile|readFileSync|readdir|readdirSync|stat|statSync|access|accessSync|existsSync|createReadStream)\s*\("""), "fs.read*", CapabilityAction.READ),
    (re.compile(r"""\bfsPromises\s*\.\s*(readFile|readdir|stat|access)\s*\("""), "fs/promises.read*", CapabilityAction.READ),
    (re.compile(r"""from\s+['"]fs\/promises['"]"""), "fs/promises import", CapabilityAction.READ),
    (re.compile(r"""require\s*\(\s*['"]fs\/promises['"]\s*\)"""), "fs/promises require", CapabilityAction.READ),
    # fs write
    (re.compile(r"""\bfs\s*\.\s*(writeFile|writeFileSync|appendFile|appendFileSync|mkdir|mkdirSync|createWriteStream|rename|renameSync|copyFile|copyFileSync)\s*\("""), "fs.write*", CapabilityAction.WRITE),
    (re.compile(r"""\bfsPromises\s*\.\s*(writeFile|appendFile|mkdir|rename|copyFile)\s*\("""), "fs/promises.write*", CapabilityAction.WRITE),
    # fs delete
    (re.compile(r"""\bfs\s*\.\s*(unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync)\s*\("""), "fs.delete*", CapabilityAction.DELETE),
    (re.compile(r"""\bfsPromises\s*\.\s*(unlink|rmdir|rm)\s*\("""), "fs/promises.delete*", CapabilityAction.DELETE),
    # fs general imports (detect at least READ access)
    (re.compile(r"""require\s*\(\s*['"]fs['"]\s*\)"""), "fs require", CapabilityAction.READ),
    (re.compile(r"""from\s+['"]fs['"]"""), "fs import", CapabilityAction.READ),
    # Sensitive path patterns
    (re.compile(r"""\bpath\s*\.\s*join\s*\([^)]*['"](\.ssh|\.aws|\.gnupg|\.kube|\.config|\.bashrc|\.zshrc|\.profile|\.gitconfig|\.netrc)['"]"""), "path.join(sensitive)", CapabilityAction.READ),
]


# ── Subprocess patterns ──

SUBPROCESS_JS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""\bchild_process\s*\.\s*(exec|execSync)\s*\("""), "child_process.exec"),
    (re.compile(r"""\bchild_process\s*\.\s*(spawn|spawnSync)\s*\("""), "child_process.spawn"),
    (re.compile(r"""\bchild_process\s*\.\s*(execFile|execFileSync)\s*\("""), "child_process.execFile"),
    (re.compile(r"""\bchild_process\s*\.\s*fork\s*\("""), "child_process.fork"),
    (re.compile(r"""\b(exec|execSync|spawn|spawnSync|fork|execFile|execFileSync)\s*\("""), "child_process.*"),
    (re.compile(r"""require\s*\(\s*['"]child_process['"]\s*\)"""), "child_process require"),
    (re.compile(r"""from\s+['"]child_process['"]"""), "child_process import"),
    (re.compile(r"""require\s*\(\s*['"]shelljs['"]\s*\)"""), "shelljs"),
    (re.compile(r"""from\s+['"]shelljs['"]"""), "shelljs import"),
]


# ── Browser automation patterns ──

BROWSER_JS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""require\s*\(\s*['"]puppeteer['"]\s*\)"""), "puppeteer"),
    (re.compile(r"""from\s+['"]puppeteer['"]"""), "puppeteer import"),
    (re.compile(r"""\bpuppeteer\s*\.\s*launch\s*\("""), "puppeteer.launch"),
    (re.compile(r"""require\s*\(\s*['"]playwright['"]\s*\)"""), "playwright"),
    (re.compile(r"""from\s+['"]playwright['"]"""), "playwright import"),
    (re.compile(r"""from\s+['"]@playwright\/test['"]"""), "playwright/test import"),
    (re.compile(r"""require\s*\(\s*['"]selenium-webdriver['"]\s*\)"""), "selenium-webdriver"),
    (re.compile(r"""from\s+['"]selenium-webdriver['"]"""), "selenium-webdriver import"),
    (re.compile(r"""require\s*\(\s*['"]cheerio['"]\s*\)"""), "cheerio"),
    (re.compile(r"""from\s+['"]cheerio['"]"""), "cheerio import"),
    (re.compile(r"""require\s*\(\s*['"]jsdom['"]\s*\)"""), "jsdom"),
    (re.compile(r"""from\s+['"]jsdom['"]"""), "jsdom import"),
]


# ── Secret / env patterns ──

SECRET_JS_PATTERNS: list[tuple[re.Pattern, str]] = [
    # process.env
    (re.compile(r"""\bprocess\s*\.\s*env\s*[\.\[]"""), "process.env"),
    (re.compile(r"""\bprocess\s*\.\s*env\b"""), "process.env"),
    # dotenv
    (re.compile(r"""require\s*\(\s*['"]dotenv['"]\s*\)"""), "dotenv"),
    (re.compile(r"""from\s+['"]dotenv['"]"""), "dotenv import"),
    (re.compile(r"""\bdotenv\s*\.\s*config\s*\("""), "dotenv.config"),
    # AWS SDK credential access
    (re.compile(r"""require\s*\(\s*['"]aws-sdk['"]\s*\)"""), "aws-sdk"),
    (re.compile(r"""from\s+['"]@aws-sdk\/"""), "aws-sdk v3 import"),
    (re.compile(r"""\bAWS\s*\.\s*config\s*\.\s*credentials"""), "AWS.config.credentials"),
    # keytar
    (re.compile(r"""require\s*\(\s*['"]keytar['"]\s*\)"""), "keytar"),
    (re.compile(r"""from\s+['"]keytar['"]"""), "keytar import"),
]


# ── Crypto patterns ──

CRYPTO_JS_PATTERNS: list[tuple[re.Pattern, str, CapabilityAction]] = [
    (re.compile(r"""\bcrypto\s*\.\s*(createSign|sign)\s*\("""), "crypto.sign", CapabilityAction.SIGN),
    (re.compile(r"""\bcrypto\s*\.\s*(createCipher|createCipheriv|publicEncrypt)\s*\("""), "crypto.encrypt", CapabilityAction.ENCRYPT),
    (re.compile(r"""\bcrypto\s*\.\s*(createHash|createHmac)\s*\("""), "crypto.hash", CapabilityAction.HASH),
    (re.compile(r"""require\s*\(\s*['"]crypto['"]\s*\)"""), "crypto require", CapabilityAction.HASH),
    (re.compile(r"""from\s+['"]crypto['"]"""), "crypto import", CapabilityAction.HASH),
    (re.compile(r"""require\s*\(\s*['"]bcrypt['"]\s*\)"""), "bcrypt", CapabilityAction.HASH),
    (re.compile(r"""from\s+['"]bcrypt['"]"""), "bcrypt import", CapabilityAction.HASH),
    (re.compile(r"""require\s*\(\s*['"]jsonwebtoken['"]\s*\)"""), "jsonwebtoken", CapabilityAction.SIGN),
    (re.compile(r"""from\s+['"]jsonwebtoken['"]"""), "jsonwebtoken import", CapabilityAction.SIGN),
    (re.compile(r"""\bjwt\s*\.\s*(sign|verify)\s*\("""), "jwt.sign/verify", CapabilityAction.SIGN),
]


# ── Deserialization patterns ──

DESER_JS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # eval / new Function covered in prohibited
    (re.compile(r"""\bJSON\s*\.\s*parse\s*\("""), "JSON.parse", "info"),
    (re.compile(r"""\bvm\s*\.\s*(runInContext|runInNewContext|runInThisContext)\s*\("""), "vm.runIn*", "restricted"),
]


# ── Hardcoded secret patterns for JS/TS ──

JS_SECRET_NAME_PATTERN = re.compile(
    r"""(?:const|let|var)\s+(password|passwd|pwd|secret|api_?key|apikey|"""
    r"""auth_?token|access_?key|access_?token|private_?key|secret_?key|"""
    r"""token|credential|auth|signing_?key|encryption_?key|master_?key|"""
    r"""client_?secret|app_?secret|db_?password|database_?password|"""
    r"""jwt_?secret|session_?secret|cookie_?secret)"""
    r"""\s*=\s*['"`]([^'"`\n]{3,})['"`]""",
    re.IGNORECASE,
)

# Known API key patterns in JS strings
JS_KEY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"""['"`](AKIA[0-9A-Z]{16})['"`]"""), "AWS Access Key ID"),
    (re.compile(r"""['"`](ghp_[A-Za-z0-9]{36,})['"`]"""), "GitHub PAT"),
    (re.compile(r"""['"`](sk_live_[A-Za-z0-9]{20,})['"`]"""), "Stripe Live Key"),
    (re.compile(r"""['"`](xox[bpras]-[A-Za-z0-9\-]+)['"`]"""), "Slack Token"),
    (re.compile(r"""['"`](eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"`]"""), "JWT"),
]

# Connection string in JS
JS_CONN_STRING_PATTERN = re.compile(
    r"""['"`]((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^'"`\s]+)['"`]"""
)

# Placeholder values to ignore
JS_PLACEHOLDERS = {
    "todo", "changeme", "change_me", "change-me",
    "replace_me", "replace-me", "your_key_here", "your-key-here",
    "xxx", "xxxx", "xxxxx", "placeholder", "example",
    "test", "testing", "dummy", "fake", "mock", "sample",
}


def _strip_js_comments(line: str) -> str:
    """Strip single-line comments from a JS line (best-effort)."""
    in_single = False
    in_double = False
    in_backtick = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
        elif ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
        elif ch == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
        elif ch == "/" and not in_single and not in_double and not in_backtick:
            if i + 1 < len(line) and line[i + 1] == "/":
                return line[:i]
    return line


def _try_extract_string_arg(line: str, pattern_end_pos: int) -> str | None:
    """Try to extract a string literal argument after a pattern match.

    Looks for the first quoted string after the match position.
    """
    rest = line[pattern_end_pos:]
    m = re.search(r"""['"]([^'"]+)['"]""", rest)
    if m:
        return m.group(1)
    return None


def parse_js_file(
    file_path: Path, relative_name: str
) -> tuple[list[Finding], list[Finding], list[ScopedCapability]]:
    """Parse a JS/TS file and extract findings + capabilities.

    Returns:
        (prohibited_findings, restricted_findings, capabilities)
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return [], [], []

    prohibited: list[Finding] = []
    restricted: list[Finding] = []
    capabilities: list[ScopedCapability] = []

    # Track already-seen capabilities to avoid duplicates
    seen_caps: set[tuple[str, str]] = set()

    lines = content.splitlines()

    # Check if we're in a multiline comment
    in_block_comment = False

    for line_num, raw_line in enumerate(lines, start=1):
        # Handle block comments
        line = raw_line
        if in_block_comment:
            end_idx = line.find("*/")
            if end_idx >= 0:
                in_block_comment = False
                line = line[end_idx + 2:]
            else:
                continue

        # Remove block comment starts within line
        while "/*" in line:
            start_idx = line.find("/*")
            end_idx = line.find("*/", start_idx + 2)
            if end_idx >= 0:
                line = line[:start_idx] + line[end_idx + 2:]
            else:
                line = line[:start_idx]
                in_block_comment = True
                break

        line = _strip_js_comments(line).strip()
        if not line:
            continue

        # ── Prohibited patterns ──
        for pattern, message in PROHIBITED_JS_PATTERNS:
            if pattern.search(line):
                prohibited.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern=pattern.pattern.strip()[:60],
                        severity=FindingSeverity.PROHIBITED,
                        message=message,
                    )
                )

        # ── Network patterns ──
        for pattern, cmd_name, _ in NETWORK_JS_PATTERNS:
            m = pattern.search(line)
            if m:
                # Try to extract URL scope
                scope = ["*"]
                scope_resolved = False
                url_arg = _try_extract_string_arg(line, m.end())
                if url_arg and (url_arg.startswith("http") or url_arg.startswith("/")):
                    scope = [url_arg]
                    scope_resolved = True

                cap_key = ("network", "connect")
                cap = ScopedCapability(
                    category=CapabilityCategory.NETWORK,
                    action=CapabilityAction.CONNECT,
                    scope=scope,
                    scope_resolved=scope_resolved,
                )
                if cap_key not in seen_caps:
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Network access: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Filesystem patterns ──
        for pattern, cmd_name, action in FS_JS_PATTERNS:
            if pattern.search(line):
                cat_action = ("fs", action.value)
                if cat_action not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.FS,
                        action=action,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Filesystem access: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cat_action)
                break

        # ── Subprocess patterns ──
        for pattern, cmd_name in SUBPROCESS_JS_PATTERNS:
            if pattern.search(line):
                cap_key = ("subprocess", "exec")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.SUBPROCESS,
                        action=CapabilityAction.EXEC,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Subprocess execution: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Browser automation patterns ──
        for pattern, cmd_name in BROWSER_JS_PATTERNS:
            if pattern.search(line):
                cap_key = ("browser", "control")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.BROWSER,
                        action=CapabilityAction.CONTROL,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Browser automation: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Secret / env patterns ──
        for pattern, cmd_name in SECRET_JS_PATTERNS:
            if pattern.search(line):
                cap_key = ("secret", "access")
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.SECRET,
                        action=CapabilityAction.ACCESS,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Secret/credential access: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Crypto patterns ──
        for pattern, cmd_name, action in CRYPTO_JS_PATTERNS:
            if pattern.search(line):
                cap_key = ("crypto", action.value)
                if cap_key not in seen_caps:
                    cap = ScopedCapability(
                        category=CapabilityCategory.CRYPTO,
                        action=action,
                        scope=["*"],
                        scope_resolved=False,
                    )
                    restricted.append(
                        Finding(
                            file=relative_name,
                            line=line_num,
                            col=0,
                            pattern=cmd_name,
                            severity=FindingSeverity.RESTRICTED,
                            capability=cap,
                            message=f"Cryptographic operation: {cmd_name}",
                        )
                    )
                    capabilities.append(cap)
                    seen_caps.add(cap_key)
                break

        # ── Deserialization patterns ──
        for pattern, cmd_name, severity_str in DESER_JS_PATTERNS:
            if pattern.search(line):
                if severity_str == "restricted":
                    cap_key = ("serial", "deserialize")
                    if cap_key not in seen_caps:
                        cap = ScopedCapability(
                            category=CapabilityCategory.SERIAL,
                            action=CapabilityAction.DESERIALIZE,
                            scope=["*"],
                            scope_resolved=False,
                        )
                        restricted.append(
                            Finding(
                                file=relative_name,
                                line=line_num,
                                col=0,
                                pattern=cmd_name,
                                severity=FindingSeverity.RESTRICTED,
                                capability=cap,
                                message=f"Deserialization: {cmd_name}",
                            )
                        )
                        capabilities.append(cap)
                        seen_caps.add(cap_key)
                break

        # ── Hardcoded secrets (variable name + value) ──
        secret_match = JS_SECRET_NAME_PATTERN.search(line)
        if secret_match:
            var_name = secret_match.group(1)
            value = secret_match.group(2)
            if value.lower().strip() not in JS_PLACEHOLDERS:
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=["hardcoded"],
                    scope_resolved=True,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern=f"hardcoded_secret:{var_name}",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"Hardcoded secret in variable '{var_name}'",
                    )
                )
                capabilities.append(cap)

        # ── Known API key patterns in strings ──
        for pattern, key_type in JS_KEY_PATTERNS:
            if pattern.search(line):
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=["hardcoded"],
                    scope_resolved=True,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern=f"hardcoded_key:{key_type}",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"Possible {key_type} detected in string literal",
                    )
                )
                capabilities.append(cap)
                break

        # ── Connection strings ──
        conn_match = JS_CONN_STRING_PATTERN.search(line)
        if conn_match:
            conn_str = conn_match.group(1)
            # Check for embedded credentials
            if re.search(r"""://[^/]+:[^/]+@""", conn_str):
                cap = ScopedCapability(
                    category=CapabilityCategory.SECRET,
                    action=CapabilityAction.ACCESS,
                    scope=["hardcoded"],
                    scope_resolved=True,
                )
                restricted.append(
                    Finding(
                        file=relative_name,
                        line=line_num,
                        col=0,
                        pattern="connection_string",
                        severity=FindingSeverity.RESTRICTED,
                        capability=cap,
                        message=f"Connection string with embedded credentials",
                    )
                )
                capabilities.append(cap)

    return prohibited, restricted, capabilities
