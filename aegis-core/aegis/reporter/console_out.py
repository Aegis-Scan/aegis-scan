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

"""Rich terminal output for scan results — narrative edition.

Every section answers three questions a human actually asks:
  1. What did you find?
  2. Why should I care?
  3. What should I do about it?

Technical details (file paths, line numbers, AST patterns) are still
available via --verbose, but the default output reads like a security
briefing, not a compiler dump.
"""

from __future__ import annotations

import sys
import textwrap
from collections import defaultdict
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegis.models.capabilities import (
    CombinationRisk,
    Finding,
    FindingSeverity,
    MetaInsight,
    MetaInsightSeverity,
    PERSONA_DISPLAY,
    PersonaClassification,
    PersonaType,
)
from aegis.models.report import ScanReport


def _make_console() -> Console:
    """Console with soft wrap. No fixed width — uses live terminal size (grows/shrinks on resize)."""
    return Console(soft_wrap=True)


console = _make_console()


def _wrap_line(line: str, width: int) -> str:
    """Wrap a single line to width, preserving leading indent on wrapped portions."""
    if len(line) <= width:
        return line
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    return textwrap.fill(
        stripped,
        width=width,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=False,
    )


def _wrap_block(text: str, width: int) -> str:
    """Wrap a multi-line block. Preserves paragraph breaks (\\n\\n) and indentation."""
    width = max(30, width)
    out: list[str] = []
    for para in text.split("\n\n"):
        lines = []
        for line in para.split("\n"):
            lines.append(_wrap_line(line, width))
        out.append("\n".join(lines))
    return "\n\n".join(out)


def _wrap_panel_content(renderable: Any, width: int) -> Any:
    """Wrap string content in a Panel renderable for the given width."""
    if isinstance(renderable, str):
        return _wrap_block(renderable, width)
    if isinstance(renderable, Group):
        wrapped = []
        for r in renderable.renderables:
            if isinstance(r, str):
                wrapped.append(_wrap_block(r, width))
            else:
                wrapped.append(r)
        return Group(*wrapped)
    return renderable


def _safe_print(*args: Any, **kwargs: Any) -> None:
    """Print with wrapping and no crop. Uses current terminal width (responds to resize)."""
    kwargs.setdefault("crop", False)
    kwargs.setdefault("overflow", "fold")
    # Pre-wrap Panel content so text never overflows; width updates on terminal resize
    if args and hasattr(args[0], "renderable") and hasattr(args[0], "border_style"):
        panel = args[0]
        try:
            w = console.width - 6  # panel padding and borders
            if w >= 30:
                wrapped = _wrap_panel_content(panel.renderable, w)
                panel_kwargs: dict[str, Any] = {}
                for k in ("title", "title_align", "border_style", "expand", "safe_box"):
                    if hasattr(panel, k):
                        panel_kwargs[k] = getattr(panel, k)
                panel_kwargs.setdefault("expand", True)
                panel_kwargs.setdefault("safe_box", True)
                args = (Panel(wrapped, **panel_kwargs),) + args[1:]
        except Exception:
            pass
    console.print(*args, **kwargs)


# ── Verdict icons ──────────────────────────────────────────────────
# These replace raw severity strings with human-scannable indicators.

ICON_PASS = "[bold green][OK][/bold green]"
ICON_WARN = "[bold yellow][WARN][/bold yellow]"
ICON_DANGER = "[bold red][ALERT][/bold red]"
ICON_INFO = "[bold blue][INFO][/bold blue]"

UNICODE_OK = "utf" in (sys.stdout.encoding or "").lower()


# ── Capability narratives ──────────────────────────────────────────
# Each entry tells the reader what a category means in plain English,
# why it matters to them, and the worst realistic thing that can happen.

CAPABILITY_NARRATIVES: dict[str, dict[str, str]] = {
    "fs": {
        "title": "FILE SYSTEM ACCESS",
        "what_it_does": (
            "This skill can {actions} files on your computer. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "File access is the most basic way a skill touches your data. "
            "Read access lets it see anything you can see. Write access lets "
            "it change existing files or plant new ones. Delete access means "
            "your data could disappear permanently."
        ),
        "how_it_hurts": (
            "A skill with file write access could overwrite your shell "
            "configuration (~/.bashrc, ~/.zshrc) to run attacker code every "
            "time you open a terminal. With read access it could scan for "
            "credentials, SSH keys, or personal documents and hand them to "
            "another capability (like network access) for exfiltration."
        ),
    },
    "network": {
        "title": "NETWORK ACCESS",
        "what_it_does": (
            "This skill can {actions} over the network. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Network access is the escape hatch. Without it, even a "
            "malicious skill is trapped on your machine. With it, anything "
            "the skill can read — files, credentials, clipboard — can leave "
            "your computer entirely and land on a server you don't control."
        ),
        "how_it_hurts": (
            "The most common abuse is silent data exfiltration: the skill "
            "reads something sensitive and POSTs it to an external endpoint "
            "buried in the code. You'd never see it happen. Inbound listeners "
            "are even worse — they open a port on your machine that remote "
            "attackers can connect to."
        ),
    },
    "subprocess": {
        "title": "PROGRAM EXECUTION",
        "what_it_does": (
            "This skill can launch other programs on your computer. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Subprocess execution is the most powerful capability a skill "
            "can have. It means the skill isn't limited to Python — it can "
            "run any program installed on your system with your full user "
            "permissions. This effectively bypasses all other restrictions."
        ),
        "how_it_hurts": (
            "A skill that can run arbitrary commands can install software, "
            "modify system settings, create new user accounts, or download "
            "and execute malware. If the commands aren't pinned to specific "
            "literal strings in the code, the skill could construct any "
            "command at runtime — and Aegis can't predict what that will be."
        ),
    },
    "env": {
        "title": "ENVIRONMENT VARIABLES",
        "what_it_does": (
            "This skill can {actions} your environment variables. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Environment variables are where most developers store secrets: "
            "API keys, database passwords, cloud credentials, auth tokens. "
            "A skill that reads environment variables has access to whatever "
            "secrets you've set — even ones meant for other tools."
        ),
        "how_it_hurts": (
            "Your OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, DATABASE_URL, and "
            "similar secrets live in environment variables. A skill that reads "
            "them can silently capture your cloud credentials, run up your "
            "API bills, or access your databases. If it also has network "
            "access, those secrets can be sent elsewhere in milliseconds."
        ),
    },
    "browser": {
        "title": "BROWSER AUTOMATION",
        "what_it_does": (
            "This skill can control a web browser — navigating to pages, "
            "clicking buttons, filling forms, and reading page content. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Browser automation means this skill can impersonate you on any "
            "website. If you're logged into your bank, email, or cloud "
            "console, the skill can interact with those sessions as you. "
            "This is the digital equivalent of handing someone your unlocked "
            "phone."
        ),
        "how_it_hurts": (
            "A malicious skill with browser control could: transfer money "
            "from your bank, read and send emails as you, change passwords "
            "on your accounts, make purchases, or approve OAuth permissions "
            "that grant long-term access to your accounts — all silently "
            "in a headless browser you never see."
        ),
    },
    "secret": {
        "title": "CREDENTIAL & SECRET ACCESS",
        "what_it_does": (
            "This skill can {actions} credentials stored in your system's "
            "secret manager (keychain, credential store, vault). "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Your system keychain stores the most sensitive credentials you "
            "have: login passwords, API tokens, encryption keys, SSH "
            "passphrases. Unlike environment variables, these are meant to "
            "be the most protected secrets on your machine."
        ),
        "how_it_hurts": (
            "If a skill can read your keychain, it can access every saved "
            "password and token on your system. Combined with network access, "
            "this is the fastest path to complete account takeover — your "
            "email, cloud infrastructure, source code repositories, and "
            "financial accounts could all be compromised in seconds."
        ),
    },
    "crypto": {
        "title": "CRYPTOGRAPHIC OPERATIONS",
        "what_it_does": (
            "This skill performs cryptographic operations: {actions}. "
            "{scope_detail}"
        ),
        "why_it_matters": (
            "Cryptographic operations are legitimate for many tools, but "
            "signing and encryption capabilities deserve scrutiny. A skill "
            "that can sign data could forge your digital identity. A skill "
            "that encrypts could ransomware your files."
        ),
        "how_it_hurts": (
            "Signing capability means the skill could create digitally "
            "signed artifacts that appear to come from you — commits, "
            "packages, documents. Encryption without your explicit intent "
            "could lock you out of your own files."
        ),
    },
    "serial": {
        "title": "DATA DESERIALIZATION",
        "what_it_does": (
            "This skill deserializes data from formats like pickle, marshal, "
            "or YAML. {scope_detail}"
        ),
        "why_it_matters": (
            "Deserialization is one of the most exploited vulnerability "
            "classes in software. Formats like Python's pickle can execute "
            "arbitrary code when loaded — the data itself IS code. Even "
            "YAML has dangerous load modes that allow code execution."
        ),
        "how_it_hurts": (
            "If this skill loads pickle files or uses yaml.load() without "
            "safe_load, anyone who can control the input data can execute "
            "arbitrary code on your machine. This is a well-known attack "
            "vector used in supply-chain compromises — the attacker poisons "
            "a data file, and the skill does the rest."
        ),
    },
    "concurrency": {
        "title": "CONCURRENT EXECUTION",
        "what_it_does": (
            "This skill uses multi-threading, multi-processing, or async "
            "execution patterns. {scope_detail}"
        ),
        "why_it_matters": (
            "Concurrency is common in legitimate tools but makes malicious "
            "behavior harder to detect. Background threads can perform "
            "actions while the skill appears to be doing something innocent "
            "in the foreground."
        ),
        "how_it_hurts": (
            "A skill could spawn a background thread that silently "
            "exfiltrates data while the main thread does legitimate work. "
            "The background activity wouldn't show up in the skill's visible "
            "output, making it much harder to notice."
        ),
    },
    "system": {
        "title": "SYSTEM-LEVEL ACCESS",
        "what_it_does": (
            "This skill accesses system-level information or installs "
            "signal handlers. {scope_detail}"
        ),
        "why_it_matters": (
            "System-level access gives the skill visibility into your "
            "machine's configuration, running processes, user accounts, and "
            "hardware. Signal handlers can intercept termination attempts, "
            "making the skill harder to stop."
        ),
        "how_it_hurts": (
            "System info gathering is a common reconnaissance step in "
            "attacks — the skill maps your environment before acting. "
            "Signal handlers can catch Ctrl+C and prevent you from stopping "
            "the skill, or trigger cleanup code that hides evidence."
        ),
    },
}


# ── Combination risk narratives ────────────────────────────────────
# Each combination gets a full story explaining the attack, not just
# a technical label.

COMBINATION_NARRATIVES: dict[str, dict[str, str]] = {
    "automated-purchasing": {
        "title": "AUTOMATED PURCHASING",
        "story": (
            "This skill can control your browser, read your stored "
            "credentials, and communicate over the network. Together, these "
            "three capabilities enable it to make purchases on your behalf "
            "without asking — logging into shopping sites with your saved "
            "passwords, adding items to cart, and completing checkout. "
            "You'd only find out when the credit card bill arrives."
        ),
        "real_world": (
            "This is not theoretical. Browser automation + credential access "
            "is the exact technique used by fraud bots. The network capability "
            "allows the skill to receive instructions from a remote server "
            "about what to buy and where to send it."
        ),
    },
    "rce-pipeline": {
        "title": "REMOTE CODE EXECUTION PIPELINE",
        "story": (
            "This skill can download content from the internet, save it to "
            "your disk, and then execute it as a program. This is the textbook "
            "definition of a Remote Code Execution (RCE) pipeline — the same "
            "mechanism used by malware droppers. The skill becomes a delivery "
            "vehicle for any code an attacker wants to run on your machine."
        ),
        "real_world": (
            "RCE pipelines are the backbone of modern malware distribution. "
            "The initial skill looks harmless, but at runtime it downloads "
            "a second-stage payload — a cryptominer, ransomware, backdoor, "
            "or credential stealer — and executes it with your permissions."
        ),
    },
    "secret-exfiltration": {
        "title": "SECRET EXFILTRATION",
        "story": (
            "This skill can read your credentials and send data over the "
            "network. That's all an attacker needs to steal your secrets. "
            "The skill reads your API keys, passwords, or tokens from your "
            "keychain or environment, then transmits them to an external "
            "server. The entire theft takes milliseconds and produces no "
            "visible output."
        ),
        "real_world": (
            "Credential theft via malicious tools is the #1 vector for "
            "cloud account compromises. One stolen AWS key can cost tens of "
            "thousands of dollars in unauthorized compute charges, and "
            "a stolen GitHub token can compromise every repository you "
            "have access to."
        ),
    },
    "supply-chain-autoload": {
        "title": "SUPPLY CHAIN RISK",
        "story": (
            "This skill executes external programs that are not on any known "
            "allow-list. This means it's running software that Aegis cannot "
            "verify — the skill is only as trustworthy as every program it "
            "calls, and those programs haven't been reviewed."
        ),
        "real_world": (
            "Supply chain attacks work by compromising a dependency rather "
            "than the main tool. If this skill calls an unvetted binary, "
            "an attacker could replace that binary with a malicious version. "
            "The skill itself looks clean, but the program it launches does "
            "the damage."
        ),
    },
}


# ── Sensitive path explanations ────────────────────────────────────
# People don't know what ~/.ssh/id_rsa means. Tell them.

PATH_EXPLANATIONS: dict[str, str] = {
    "~/.ssh": (
        "Your SSH keys — the private keys that let you log into remote "
        "servers without a password. Anyone with these files can access "
        "your servers, GitHub repos, and cloud instances as you."
    ),
    "~/.gnupg": (
        "Your GPG keys — used for signing commits, encrypting emails, "
        "and verifying software. A stolen GPG key lets someone forge "
        "your digital signature."
    ),
    "~/.aws": (
        "Your AWS credentials — access keys that control your cloud "
        "infrastructure, billing, databases, and storage. A compromised "
        "AWS key is one of the most expensive security incidents possible."
    ),
    "~/.kube": (
        "Your Kubernetes config — connection details and tokens for your "
        "container clusters. Access to this file means full control over "
        "your deployed applications."
    ),
    "~/.azure": (
        "Your Azure credentials — access to your Microsoft cloud "
        "resources, virtual machines, databases, and storage accounts."
    ),
    "~/.bashrc": (
        "Your shell startup file — commands in this file run every time "
        "you open a terminal. Writing to it means the attacker's code "
        "runs automatically, forever, every time you work."
    ),
    "~/.zshrc": (
        "Your shell startup file — same as .bashrc but for zsh. Anything "
        "written here executes every time you open a terminal window."
    ),
    "~/.profile": (
        "Your login profile — runs on every login session. Modifying it "
        "means malicious code runs every time you log in."
    ),
    "~/.gitconfig": (
        "Your Git configuration — contains your identity, credential "
        "helpers, and possibly authentication tokens. Modifying it could "
        "redirect your pushes to a malicious repository."
    ),
    "~/.netrc": (
        "Your .netrc file — stores plaintext login credentials for "
        "network services. Any tool with read access to this file can "
        "harvest your usernames and passwords."
    ),
    "/etc": (
        "System configuration — modifying files here can change DNS "
        "resolution, add user accounts, alter system services, and "
        "install persistent backdoors."
    ),
}


# ── Human-readable action labels ──────────────────────────────────

ACTION_VERBS: dict[str, dict[str, str]] = {
    "fs": {"read": "read", "write": "write to", "delete": "delete"},
    "network": {
        "connect": "make outbound connections",
        "listen": "open ports and listen for incoming connections",
        "dns": "perform DNS lookups",
    },
    "subprocess": {
        "exec": "execute programs",
        "spawn": "spawn child processes",
    },
    "env": {
        "read": "read",
        "write": "modify",
    },
    "browser": {
        "control": "control",
        "navigate": "navigate",
        "inject": "inject content into pages",
    },
    "secret": {
        "access": "access stored credentials",
        "store": "write to credential stores",
        "delete": "delete stored credentials",
    },
    "crypto": {
        "sign": "sign data",
        "encrypt": "encrypt data",
        "hash": "hash data",
    },
    "serial": {
        "deserialize": "deserialize data (potential code execution)",
    },
    "concurrency": {
        "thread": "multi-threading",
        "process": "multi-processing",
        "async": "async execution",
    },
    "system": {
        "signal": "install signal handlers",
        "sysinfo": "read system information",
    },
}


# ── Helper functions ───────────────────────────────────────────────


def _risk_color(score: int) -> str:
    if score >= 75:
        return "bold red"
    elif score >= 50:
        return "bold dark_orange"
    elif score >= 25:
        return "bold yellow"
    return "bold green"


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def _risk_bar(score: int) -> Text:
    """Build a visual risk bar. Uses Text with 2 segments to avoid boundary glitches."""
    filled = min(20, score // 5)
    empty = 20 - filled
    if score >= 75:
        style = "red"
    elif score >= 50:
        style = "dark_orange"
    elif score >= 25:
        style = "yellow"
    else:
        style = "green"
    bar = Text()
    bar.append("#" * filled, style=style)
    bar.append("-" * empty, style="dim")
    return bar


def _section_icon(severity: str) -> str:
    """Return a verdict icon for a section based on severity."""
    s = severity.lower()
    if s in ("critical", "prohibited", "high"):
        return ICON_DANGER
    elif s in ("medium", "restricted", "warning"):
        return ICON_WARN
    elif s in ("info",):
        return ICON_INFO
    return ICON_PASS


def _persona_icon(persona: PersonaClassification | None) -> str:
    if not persona:
        return "?"
    if not UNICODE_OK:
        return "[*]"
    info = PERSONA_DISPLAY.get(persona.persona.value, {})
    return info.get("icon", "*")


def _severity_word(category: str, actions: dict[str, list[str]]) -> str:
    """Determine severity for a capability category based on its actions/scopes."""
    has_wildcard = any("*" in scopes for scopes in actions.values())
    high_risk_cats = {"subprocess", "browser", "secret", "serial"}

    if category in high_risk_cats:
        return "high" if has_wildcard else "warning"
    elif category in {"network", "fs", "env"}:
        return "warning" if has_wildcard else "medium"
    return "info"


def _scope_summary(scopes: list[str]) -> str:
    if not scopes or scopes == ["*"]:
        return "any path (the target could not be determined from the code)"
    if len(scopes) == 1:
        return f'specifically "{scopes[0]}"'
    if len(scopes) <= 3:
        quoted = [f'"{s}"' for s in scopes]
        return ", ".join(quoted[:-1]) + f", and {quoted[-1]}"
    quoted = [f'"{s}"' for s in scopes[:2]]
    return f'{", ".join(quoted)}, and {len(scopes) - 2} other targets'


def _build_action_sentence(category: str, actions: dict[str, list[str]]) -> str:
    """Build a natural sentence describing what actions a category performs."""
    verbs = ACTION_VERBS.get(category, {})
    parts = []
    for action, scopes in actions.items():
        verb = verbs.get(action, action)
        scope_desc = _scope_summary(scopes)
        parts.append(f"{verb} {scope_desc}")
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def _count_unique_files(findings: list[Finding]) -> int:
    return len({f.file for f in findings})


def _find_matching_path_explanation(scope: str) -> str | None:
    """Find the best matching explanation for a path violation scope."""
    for pattern, explanation in PATH_EXPLANATIONS.items():
        if pattern in scope or scope.startswith(pattern.replace("~", "")):
            return explanation
    return None


def _ascii_safe(text: str) -> str:
    """Return text safe for legacy Windows terminals."""
    if not text:
        return ""
    normalized = (
        text.replace("\u2192", "->")
        .replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("\u2026", "...")
        .replace("\u00a0", " ")
    )
    return normalized.encode("ascii", "replace").decode("ascii")


def _truncate(text: str, max_len: int) -> str:
    """Shorten text only for JSON/internal use. Never used in human output."""
    text = _ascii_safe(text)
    if len(text) <= max_len:
        return text
    # Find last space before limit to avoid mid-word cuts
    cutpoint = text.rfind(" ", 0, max_len - 3)
    if cutpoint < max_len // 2:
        cutpoint = max_len - 3
    return text[:cutpoint].rstrip() + " ..."


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _is_internal_scope(scope: str) -> bool:
    """Return True if a scope value is an internal Aegis label rather than a real target."""
    return (
        scope.startswith("deterministic.")
        or scope.startswith("aegis.")
        or scope.startswith("_")
    )


def _compact_scope_text(scopes: list[str], unresolved: bool = False) -> str:
    if not scopes:
        return "-"
    cleaned = _dedupe([
        _ascii_safe(scope)
        for scope in scopes
        if not _is_internal_scope(scope)
    ])
    if not cleaned:
        return "internal references only"
    if cleaned == ["*"]:
        return "* (unresolved)"
    if len(cleaned) <= 3:
        base = ", ".join(cleaned)
    else:
        base = ", ".join(cleaned[:2]) + f", +{len(cleaned) - 2} more"
    if unresolved:
        return f"{base} (partial unresolved)"
    return base


# ── Print functions ────────────────────────────────────────────────


def print_scan_header(
    target: str,
    file_count: int,
    manifest_source: str,
    python_count: int = 0,
    shell_count: int = 0,
    js_count: int = 0,
    config_count: int = 0,
    docker_count: int = 0,
    scan_mode: str | None = None,
) -> None:
    """Print scan header with file type breakdown."""
    safe_target = _ascii_safe(target)
    safe_source = _ascii_safe(manifest_source)
    safe_mode = _ascii_safe(scan_mode) if scan_mode else None

    header = Text()
    header.append("AEGIS SECURITY AUDIT\n", style="bold cyan")
    header.append(f"  Target: {safe_target}\n", style="white")

    breakdown = []
    if python_count:
        breakdown.append(f"{python_count} Python")
    if js_count:
        breakdown.append(f"{js_count} JS/TS")
    if shell_count:
        breakdown.append(f"{shell_count} shell")
    if config_count:
        breakdown.append(f"{config_count} config")
    if docker_count:
        breakdown.append(f"{docker_count} Dockerfile")
    other = file_count - python_count - shell_count - js_count - config_count - docker_count
    if other > 0:
        breakdown.append(f"{other} other")

    if breakdown:
        header.append(
            f"  Files:  {file_count} ({', '.join(breakdown)})\n",
            style="white",
        )
    else:
        header.append(f"  Files:  {file_count}\n", style="white")

    header.append(f"  Source: {safe_source}\n", style="dim")
    if safe_mode:
        header.append(f"  Mode:   {safe_mode}", style="dim")

    _safe_print(
        Panel(
            header,
            border_style="white",
            title="[bold]Aegis Security Audit[/bold]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_executive_summary(
    capabilities: dict[str, dict[str, list[str]]],
    prohibited_count: int,
    combination_risks: list[CombinationRisk],
    path_violations: list[dict[str, Any]],
    risk_score: int,
    meta_insights: list[MetaInsight] | None = None,
) -> None:
    """Print a concise, specific verdict — names the actual finding, not boilerplate.

    The verdict should hit you on the head: what's the single most important
    thing you need to know about this skill?
    """
    meta_insights = meta_insights or []
    meta_warnings = [
        i
        for i in meta_insights
        if i.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)
    ]

    if prohibited_count > 0:
        icon = ICON_DANGER
        verdict = (
            "[bold red]BLOCKED[/bold red] — Contains dynamic code execution "
            "(eval/exec). Cannot be certified."
        )
        border = "red"
    elif risk_score >= 75:
        icon = ICON_DANGER
        parts = []
        if "subprocess" in capabilities:
            parts.append("execute programs")
        if "browser" in capabilities:
            parts.append("control your browser")
        if "secret" in capabilities:
            parts.append("read stored credentials")
        if "network" in capabilities:
            parts.append("send data over the network")
        if "fs" in capabilities and any(
            "*" in s for scopes in capabilities["fs"].values() for s in scopes
        ):
            parts.append("access files across your system")

        if parts:
            verdict = (
                f"This skill can {', '.join(parts)}. "
                "Do not install without careful review."
            )
        else:
            verdict = "Critical risk. Do not install without careful review."
        if meta_warnings:
            verdict += (
                f" Plus {len(meta_warnings)} documentation concern(s) "
                "— see Trust Analysis."
            )
        border = "red"
    elif risk_score >= 50:
        icon = ICON_WARN
        cap_names = {
            "fs": "file access",
            "network": "network",
            "subprocess": "program execution",
            "env": "env vars",
            "browser": "browser control",
            "secret": "credentials",
        }
        found = [cap_names.get(c, c) for c in capabilities if c in cap_names]
        if found:
            verdict = (
                f"Requests {', '.join(found)} with broad scope. "
                "Review each section below."
            )
        else:
            verdict = "Elevated risk. Review findings below."
        if meta_warnings:
            verdict += (
                f" Also found {len(meta_warnings)} trust concern(s) "
                "in the documentation."
            )
        border = "yellow"
    elif risk_score >= 25:
        icon = ICON_WARN
        cap_count = sum(len(a) for a in capabilities.values())

        if meta_warnings:
            verdict = (
                f"Low code risk ({cap_count} minor API(s)), but the "
                "documentation is misleading — the SKILL.md makes claims "
                "the code doesn't support. See Trust Analysis below."
            )
        else:
            verdict = (
                f"Minor. {cap_count} restricted API(s) with mostly "
                "well-defined scope. Quick review recommended."
            )
        border = "cyan"
    else:
        if capabilities:
            icon = ICON_PASS
            verdict = "Clean. Only well-scoped, low-risk capabilities detected."
        else:
            icon = ICON_PASS
            verdict = (
                "Clean. Permissions: minimal. No high-risk APIs (network, "
                "subprocess, credentials) detected."
            )

        if meta_warnings:
            icon = ICON_WARN
            verdict += (
                f" However, {len(meta_warnings)} documentation concern(s) "
                "found — see Trust Analysis below."
            )
            border = "yellow"
        else:
            border = "green"

    # Compact callouts for critical combinations and path violations
    callouts = []
    crit_combos = [r for r in combination_risks if r.severity == "critical"]
    if crit_combos:
        names = [
            COMBINATION_NARRATIVES.get(r.rule_id, {}).get("title", r.rule_id)
            for r in crit_combos
        ]
        callouts.append(
            f"{ICON_DANGER}  Dangerous combination: {', '.join(names)}"
        )
    if path_violations:
        callouts.append(
            f"{ICON_DANGER}  Accesses {len(path_violations)} sensitive "
            "system path(s)"
        )
    if callouts:
        verdict += "\n\n  " + "\n  ".join(callouts)

    _safe_print(
        Panel(
            f"  {icon}  {verdict}",
            border_style=border,
            title=f"[bold {border}]Verdict[/bold {border}]",
            expand=True,
            safe_box=True,
        )
    )


def print_risk_score(
    static: int,
    llm_adj: int,
    final: int,
    summary_text: str = "",
) -> None:
    """Print risk score with visual bar."""
    color = _risk_color(final)
    level = _risk_level(final)
    bar = _risk_bar(final)

    score_line = (
        f"  {bar}  "
        f"[{color.replace('bold ', '')}]{final}/100  {level}"
        f"[/{color.replace('bold ', '')}]"
    )

    detail = f"\n\n  [dim]Static analysis: {static}[/dim]"
    if llm_adj:
        sign = "+" if llm_adj > 0 else ""
        detail += f"  [dim]AI adjustment: {sign}{llm_adj}[/dim]"

    _safe_print(
        Panel(
            score_line + detail,
            border_style=color.replace("bold ", ""),
            title=f"[{color}]Risk Score[/{color}]",
            expand=True,
            safe_box=True,
        )
    )


def print_prohibited_findings(findings: list[Finding]) -> None:
    """Print prohibited findings — the hard blockers.

    Each finding shows:
    - The actual source code line (if available)
    - Function/class context (where in the code this lives)
    - CWE reference for industry-standard classification
    - Plain English explanation of the danger
    - Suggested fix (if available)
    """
    if not findings:
        return

    file_count = _count_unique_files(findings)

    body = (
        f"  {ICON_DANGER}  [bold red]BLOCKED[/bold red] — This skill cannot "
        f"be certified.\n\n"
        f"  Found {len(findings)} prohibited pattern(s) in {file_count} file(s). "
        "These are code constructs that can never be safe in a skill — they "
        "allow the skill to execute arbitrary code that Aegis cannot analyze "
        "or predict.\n"
    )

    for f in findings:
        explanation = _prohibited_explanation(f.pattern)

        # Location with function context
        location = f"[white]{_ascii_safe(f.file)}[/white] line {f.line}"
        if f.function_context:
            location += f" in [white]{_ascii_safe(f.function_context)}[/white]"

        # CWE badge
        cwe_badge = ""
        if f.cwe_ids:
            cwe_badge = f"  [dim]{', '.join(f.cwe_ids[:2])}[/dim]"

        body += f"\n  {ICON_DANGER}  {location}{cwe_badge}\n"

        # Source code line — the most valuable piece of context
        if f.source_line:
            src = f.source_line.strip()
            if len(src) > 110:
                src = src[:107] + "..."
            body += f"     [dim]|[/dim] [italic]{_ascii_safe(src)}[/italic]\n"

        body += f"     Pattern: [red]{_ascii_safe(f.pattern)}[/red]\n"
        body += f"     {_ascii_safe(explanation)}\n"

        # Risk note (if enriched) — more specific than the generic explanation
        if f.risk_note and f.risk_note != f.message:
            body += f"     [dim]{_ascii_safe(f.risk_note)}[/dim]\n"

        if f.suggested_fix:
            body += f"     [cyan]-> {_ascii_safe(f.suggested_fix)}[/cyan]\n"

    body += (
        "\n  [dim]Why this is a hard block:[/dim] These patterns give the skill "
        "the ability to run code that doesn't exist in the source files — code "
        "that could be downloaded at runtime, constructed from encrypted strings, "
        "or generated dynamically. Aegis cannot audit what doesn't exist yet."
    )

    _safe_print(
        Panel(
            body,
            border_style="red",
            title="[bold red]Prohibited Patterns[/bold red]",
            expand=True,
            safe_box=True,
        )
    )


def _prohibited_explanation(pattern: str) -> str:
    """Return a plain English explanation for a prohibited pattern."""
    explanations = {
        "eval": (
            "eval() executes any Python expression passed as a string. "
            "The string could come from user input, a network request, "
            "or an encrypted payload — Aegis can't know what it will run."
        ),
        "exec": (
            "exec() runs arbitrary Python code from a string. Unlike eval(), "
            "it can execute entire programs — creating files, making network "
            "requests, or installing backdoors. The code doesn't exist in the "
            "source until runtime."
        ),
        "compile": (
            "compile() turns strings into executable code objects. This is "
            "a building block for running code that isn't visible in the "
            "source files — a common obfuscation technique."
        ),
        "importlib": (
            "Dynamic imports load modules by name at runtime. The module name "
            "could be constructed from variables, network responses, or "
            "encrypted data — allowing the skill to load any Python module "
            "on your system."
        ),
        "ctypes": (
            "ctypes provides direct access to C libraries and raw memory. "
            "This bypasses all Python-level security and can execute native "
            "machine code, manipulate process memory, and call operating "
            "system functions directly."
        ),
        "base64": (
            "Base64 decoding fed into execution suggests obfuscated code — "
            "the skill is hiding what it actually runs by encoding it. This "
            "is a hallmark technique of malware."
        ),
    }
    for key, explanation in explanations.items():
        if key in pattern.lower():
            return explanation
    return f"This pattern ({pattern}) enables dynamic code execution that cannot be statically analyzed."


def _print_capabilities_compact(
    capabilities: dict[str, dict[str, list[str]]],
    restricted_findings: list[Finding],
) -> None:
    """Compact single-panel capability display for low-risk scans.

    Shows capabilities as a tree: category → action → source files.
    No paragraphs, no narratives — just the facts.
    """
    cat_count = len(capabilities)
    body = ""

    for idx, (category, actions) in enumerate(sorted(capabilities.items())):
        narrative = CAPABILITY_NARRATIVES.get(category, {})
        title = narrative.get("title", category.upper())
        cat_action_verbs = ACTION_VERBS.get(category, {})

        for action, scopes in sorted(actions.items()):
            verb = cat_action_verbs.get(action, action)
            has_wild = "*" in scopes
            if not scopes or scopes == ["*"]:
                scope_display = "[yellow]*[/yellow]"
            elif len(scopes) <= 3:
                scope_display = ", ".join(
                    f'"[green]{s}[/green]"' for s in scopes
                )
            else:
                scope_display = (
                    ", ".join(f'"[green]{s}[/green]"' for s in scopes[:2])
                    + f" +{len(scopes) - 2} more"
                )
            wild_tag = (
                " [yellow](unresolved)[/yellow]"
                if has_wild
                else " [green](resolved)[/green]"
            )
            body += f"  [bold]{title}[/bold]  ──  {verb}\n"
            body += f"  Scope: {scope_display}{wild_tag}\n"

        # Show source files as a tree
        related = [
            f
            for f in restricted_findings
            if f.capability and f.capability.category.value == category
        ]
        if related:
            for i, f in enumerate(related):
                connector = "└─" if i == len(related) - 1 else "├─"
                body += (
                    f"  {connector} [dim]{f.file}:{f.line}[/dim]"
                    f" — [dim]{f.pattern}[/dim]\n"
                )

        if idx < len(capabilities) - 1:
            body += "\n"

    _safe_print(
        Panel(
            body.rstrip(),
            border_style="cyan",
            title=f"[bold cyan]Capabilities ({cat_count})[/bold cyan]",
            expand=True,
            safe_box=True,
        )
    )


def _print_capabilities_expanded(
    capabilities: dict[str, dict[str, list[str]]],
    restricted_findings: list[Finding],
    verbose: bool,
) -> None:
    """Narrative capability panels for high-risk or complex scans.

    Each category gets its own panel with context on why it matters
    and how it could be abused — justified at higher risk levels.
    """
    for category, actions in sorted(capabilities.items()):
        narrative = CAPABILITY_NARRATIVES.get(category)
        if not narrative:
            continue

        severity = _severity_word(category, actions)
        icon = _section_icon(severity)
        has_wildcard = any("*" in scopes for scopes in actions.values())
        action_sentence = _build_action_sentence(category, actions)
        scope_detail = (
            "[yellow]Some targets are unresolved (wildcards) — actual "
            "scope may be broader.[/yellow]"
            if has_wildcard
            else "[green]All targets resolved to specific values.[/green]"
        )

        what = narrative["what_it_does"].format(
            actions=action_sentence, scope_detail=scope_detail
        )

        body = f"  {icon}  {what}\n"
        body += f"\n  [bold white]Why this matters:[/bold white]\n"
        body += f"  {narrative['why_it_matters']}\n"
        body += f"\n  [bold white]How this can hurt you:[/bold white]\n"
        body += f"  {narrative['how_it_hurts']}\n"

        body += f"\n  [bold white]Detected access:[/bold white]\n"
        cat_action_verbs = ACTION_VERBS.get(category, {})
        for action, scopes in sorted(actions.items()):
            verb = cat_action_verbs.get(action, action)
            scope_str = _scope_summary(scopes)
            wild = " [yellow](unresolved)[/yellow]" if "*" in scopes else ""
            body += f"    • {verb}: {scope_str}{wild}\n"

        # Always show source locations (not gated on verbose)
        related = [
            f
            for f in restricted_findings
            if f.capability
            and f.capability.category.value == category
        ]
        if related:
            body += f"\n  [dim]Source:[/dim]\n"
            for f in related[:10]:
                body += (
                    f"    [dim]{f.file}:{f.line} — "
                    f"{f.pattern}[/dim]\n"
                )
            if len(related) > 10:
                body += f"    [dim]... and {len(related) - 10} more[/dim]\n"

        border_color = {"high": "red", "warning": "yellow", "medium": "cyan"}.get(
            severity, "green"
        )

        _safe_print(
            Panel(
                body.rstrip(),
                border_style=border_color,
                title=f"[bold {border_color}]{narrative['title']}[/bold {border_color}]",
                expand=True,
                safe_box=True,
            )
        )


def print_capabilities(
    capabilities: dict[str, dict[str, list[str]]],
    restricted_findings: list[Finding],
    verbose: bool = False,
    risk_score: int = 0,
) -> None:
    """Print capability findings — compact for low risk, narrative for high risk.

    Low-risk scans (< 50, ≤ 3 categories) get a single compact panel.
    High-risk or complex scans get full narrative panels with context.
    """
    if not capabilities:
        _safe_print(
            Panel(
                f"  {ICON_PASS}  Permissions: minimal. No high-risk APIs "
                "(network, subprocess, credentials) detected.",
                border_style="green",
                title="[bold green]Capabilities[/bold green]",
                expand=True,
                safe_box=True,
            )
        )
        return

    cat_count = len(capabilities)
    use_compact = risk_score < 50 and cat_count <= 3

    if use_compact:
        _print_capabilities_compact(capabilities, restricted_findings)
    else:
        _print_capabilities_expanded(
            capabilities, restricted_findings, verbose
        )


def print_combination_risks(risks: list[CombinationRisk]) -> None:
    """Print combination risks as attack narratives.

    This is Aegis's unique differentiator — we explain the actual attack,
    not just list which capabilities overlap.
    """
    if not risks:
        return

    _safe_print()

    for risk in risks:
        narrative = COMBINATION_NARRATIVES.get(risk.rule_id)
        border = "red" if risk.severity == "critical" else "yellow"
        sev_color = "red" if risk.severity == "critical" else "yellow"

        caps = " + ".join(risk.matched_capabilities)

        if narrative:
            body = (
                f"  {ICON_DANGER}  [{sev_color}]{risk.severity.upper()}[/{sev_color}]"
                f"  —  Risk override: {risk.risk_override}/100\n\n"
                f"  [bold white]What this means:[/bold white]\n"
                f"  {narrative['story']}\n\n"
                f"  [bold white]Why you should take this seriously:[/bold white]\n"
                f"  {narrative['real_world']}\n\n"
                f"  [dim]Capabilities involved: {caps}[/dim]"
            )
        else:
            # Fallback for unknown rule IDs
            body = (
                f"  {ICON_DANGER}  [{sev_color}]{risk.severity.upper()}[/{sev_color}]"
                f"  —  Risk override: {risk.risk_override}/100\n\n"
                f"  {risk.message}\n\n"
                f"  This combination of capabilities is dangerous because together "
                f"they enable attack patterns that no single capability allows "
                f"on its own.\n\n"
                f"  [dim]Capabilities involved: {caps}[/dim]"
            )

        if risk.suggested_fix:
            body += (
                f"\n\n  [bold white]Suggested mitigation:[/bold white]\n"
                f"  [cyan]{risk.suggested_fix}[/cyan]"
            )

        title = (
            narrative["title"] if narrative else risk.rule_id.replace("-", " ").upper()
        )

        _safe_print(
            Panel(
                body,
                border_style=border,
                title=f"[bold {border}]{title}[/bold {border}]",
                expand=True,
                safe_box=True,
            )
        )


def print_external_binaries(
    binaries: list[str],
    denied: list[str],
    unrecognized: list[str],
) -> None:
    """Print external binary analysis with explanations."""
    if not binaries:
        return

    has_problems = bool(denied or unrecognized)
    icon = ICON_DANGER if denied else (ICON_WARN if unrecognized else ICON_PASS)

    body = (
        f"  {icon}  This skill launches {len(binaries)} external program(s). "
        "Each program runs with your full user permissions — anything they "
        "can do, this skill can do through them.\n"
    )

    if denied:
        body += (
            f"\n  [bold red]{len(denied)} program(s) are on the deny list:[/bold red]\n"
        )
        for b in denied:
            body += f"    {ICON_DANGER}  [red]{b}[/red] — blocked by policy\n"
        body += (
            "\n  Denied programs are powerful system tools (cloud CLIs, package "
            "managers, compilers) that could be used to modify your system, install "
            "software, or access cloud infrastructure.\n"
        )

    if unrecognized:
        body += (
            f"\n  [bold yellow]{len(unrecognized)} program(s) are not recognized:[/bold yellow]\n"
        )
        for b in unrecognized:
            body += f"    {ICON_WARN}  [yellow]{b}[/yellow] — not on any allow-list\n"
        body += (
            "\n  Unrecognized programs haven't been reviewed. They could be legitimate "
            "tools or they could be malicious binaries planted elsewhere on your system. "
            "Verify each one before trusting this skill.\n"
        )

    allowed = [b for b in binaries if b not in denied and b not in unrecognized]
    if allowed:
        body += (
            f"\n  [green]{len(allowed)} program(s) are on the allow-list:[/green] "
            f"[dim]{', '.join(allowed)}[/dim]\n"
        )

    border = "red" if denied else ("yellow" if unrecognized else "green")
    _safe_print(
        Panel(
            body.rstrip(),
            border_style=border,
            title=f"[bold {border}]External Programs[/bold {border}]",
            expand=True,
            safe_box=True,
        )
    )


def print_path_violations(violations: list[dict[str, Any]]) -> None:
    """Print path violations with explanations of what each path protects."""
    if not violations:
        return

    body = (
        f"  {ICON_DANGER}  This skill accesses {len(violations)} sensitive "
        "system path(s). These are directories that contain credentials, "
        "encryption keys, or system configuration — areas a skill should "
        "not touch unless it has a very specific, legitimate reason.\n"
    )

    for v in violations:
        scope = v.get("scope", "")
        capability = v.get("capability", "")
        deny_pattern = v.get("deny_pattern", "")

        # Find the best explanation for this path
        explanation = _find_matching_path_explanation(scope)
        if not explanation:
            explanation = _find_matching_path_explanation(deny_pattern)

        body += f"\n  {ICON_DANGER}  [red]{scope}[/red]"
        body += f"  [dim](via {capability})[/dim]\n"

        if explanation:
            body += f"     {explanation}\n"
        else:
            body += (
                f"     This path matches the sensitive pattern \"{deny_pattern}\". "
                "Skills should not access this location.\n"
            )

    body += (
        f"\n  [bold white]What to do:[/bold white] If this skill legitimately needs "
        "access to these paths (e.g., an SSH tool needs ~/.ssh), verify "
        "that it only reads what it needs and doesn't copy or transmit "
        "the contents elsewhere. If the access seems unnecessary for the "
        "skill's stated purpose, treat it as a red flag."
    )

    _safe_print(
        Panel(
            body,
            border_style="red",
            title="[bold red]Sensitive Path Access[/bold red]",
            expand=True,
            safe_box=True,
        )
    )


def print_attack_scenarios(
    capabilities: dict[str, dict[str, list[str]]],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict[str, Any]],
    external_binaries: list[str],
    denied_bins: list[str],
) -> None:
    """Generate and print realistic attack scenarios based on findings.

    This is the section that makes Aegis reports actionable — it
    connects the abstract capabilities to concrete harms.
    """
    scenarios: list[str] = []
    cap_set = set(capabilities.keys())

    # Scenario: credential theft via env + network
    if "env" in cap_set and "network" in cap_set:
        scenarios.append(
            "[bold]Credential Theft via Environment[/bold]\n"
            "  The skill reads your environment variables (where API keys and "
            "database passwords typically live) and has network access to send "
            "data externally. An attacker could harvest your OPENAI_API_KEY, "
            "AWS_SECRET_ACCESS_KEY, DATABASE_URL, and similar secrets, then "
            "transmit them to a remote server — all in a single HTTP request "
            "that takes less than a second."
        )

    # Scenario: credential theft via secrets + network
    if "secret" in cap_set and "network" in cap_set:
        scenarios.append(
            "[bold]Keychain Exfiltration[/bold]\n"
            "  The skill can read your system keychain and make network "
            "requests. Your saved passwords, SSH key passphrases, and "
            "authentication tokens could be silently copied and sent to "
            "an external server. You would see no visible indication — "
            "the theft happens in memory, with no files written to disk."
        )

    # Scenario: RCE via download + write + exec
    if "network" in cap_set and "fs" in cap_set and "subprocess" in cap_set:
        scenarios.append(
            "[bold]Remote Code Execution (Malware Dropper)[/bold]\n"
            "  The skill can download files from the internet, write them "
            "to disk, and execute them as programs. This is the exact "
            "mechanism used by malware droppers: download a payload, save "
            "it as an executable, and run it. The payload could be anything — "
            "a cryptominer, ransomware, or a persistent backdoor."
        )

    # Scenario: persistence via file write
    if "fs" in cap_set and any(
        "*" in s
        for scopes in capabilities.get("fs", {}).values()
        for s in scopes
    ):
        if path_violations:
            scenarios.append(
                "[bold]Persistent Backdoor Installation[/bold]\n"
                "  The skill has broad file write access and touches "
                "sensitive system paths. It could modify your shell startup "
                "files (~/.bashrc, ~/.zshrc) to execute attacker code every "
                "time you open a terminal — creating a backdoor that "
                "survives reboots and persists until you manually inspect "
                "those files."
            )

    # Scenario: browser session hijacking
    if "browser" in cap_set:
        scenarios.append(
            "[bold]Browser Session Hijacking[/bold]\n"
            "  The skill controls a web browser. If you're logged into "
            "any web application (email, banking, cloud console), the "
            "skill can interact with those sessions as you — reading "
            "emails, transferring funds, changing settings, or granting "
            "access to your accounts to third parties."
        )

    # Scenario: supply chain via unrecognized binaries
    if denied_bins:
        denied_str = ", ".join(denied_bins)
        scenarios.append(
            f"[bold]Privileged Tool Hijacking[/bold]\n"
            f"  The skill attempts to run: {denied_str}. These are "
            "powerful system tools that can modify your cloud infrastructure, "
            "install packages, or change system permissions. If the commands "
            "aren't pinned to specific, safe arguments, the skill could use "
            "these tools to escalate its access far beyond what a Python "
            "script normally has."
        )

    # Scenario: deserialization attack
    if "serial" in cap_set:
        scenarios.append(
            "[bold]Deserialization Code Injection[/bold]\n"
            "  The skill deserializes data from formats like pickle or "
            "YAML. If an attacker can control the input data (by "
            "tampering with a file or intercepting a download), the "
            "deserialization itself executes arbitrary code. The skill "
            "doesn't need eval() or exec() — the data format does it "
            "automatically."
        )

    if not scenarios:
        return

    body = (
        f"  Based on the capabilities detected above, here are realistic "
        "ways this skill could be weaponized if it were malicious or "
        "compromised. These aren't hypothetical — each scenario uses "
        "only the capabilities Aegis actually found in the code.\n"
    )

    for i, scenario in enumerate(scenarios, 1):
        body += f"\n  [bold cyan]{i}.[/bold cyan] {scenario}\n"

    _safe_print()
    _safe_print(
        Panel(
            body,
            border_style="yellow",
            title="[bold yellow]What Could Go Wrong[/bold yellow]",
            expand=True,
            safe_box=True,
        )
    )


def print_what_could_go_wrong_compact(
    capabilities: dict[str, dict[str, list[str]]],
    denied_bins: list[str],
    combination_risks: list[CombinationRisk] | None = None,
    path_violations: list[dict[str, Any]] | None = None,
) -> None:
    """Plain-English attack scenarios based on what Aegis actually found."""
    combination_risks = combination_risks or []
    path_violations = path_violations or []
    scenarios: list[str] = []
    cap_set = set(capabilities.keys())

    if "secret" in cap_set and "network" in cap_set:
        scenarios.append(
            "Credential theft: the skill can read stored secrets and send data "
            "over the network. A compromised version could silently exfiltrate "
            "your API keys and tokens in a single HTTP request."
        )
    elif "env" in cap_set and "network" in cap_set:
        scenarios.append(
            "Environment variable theft: the skill reads env vars (where API keys "
            "usually live) and has network access. Your OPENAI_API_KEY or "
            "AWS_SECRET_ACCESS_KEY could be sent to an external server."
        )
    if "network" in cap_set and "fs" in cap_set and "subprocess" in cap_set:
        scenarios.append(
            "Remote code execution: the skill can download files, save them to "
            "disk, and run them as programs. This is the textbook malware dropper "
            "pattern: fetch a payload, write it, execute it."
        )
    elif "network" in cap_set and "subprocess" in cap_set:
        scenarios.append(
            "Download-and-execute: the skill can fetch data from the internet and "
            "run external programs. Together, that can execute untrusted payloads."
        )
    if "browser" in cap_set:
        scenarios.append(
            "Session hijacking: the skill controls a web browser. If you are "
            "logged into any website, it can interact with your active sessions "
            "as if it were you."
        )
    if "fs" in cap_set and any(
        "*" in s for scopes in capabilities.get("fs", {}).values() for s in scopes
    ) and path_violations:
        scenarios.append(
            "Persistent backdoor: the skill has broad file access and touches "
            "sensitive system paths. It could modify shell startup files like "
            ".bashrc or .zshrc to run attacker code every time you open a terminal."
        )
    if denied_bins:
        bin_list = ", ".join(_ascii_safe(b) for b in sorted(denied_bins))
        scenarios.append(
            f"Privilege escalation: the skill tries to run policy-denied tools "
            f"({bin_list}). These are powerful system or cloud CLIs that could "
            f"modify infrastructure, install packages, or change permissions "
            f"far beyond what the skill itself needs."
        )
    if "serial" in cap_set:
        scenarios.append(
            "Deserialization attack: the skill loads data in formats like pickle "
            "or YAML that can execute code on load. If an attacker can tamper "
            "with the input, the data itself becomes the exploit."
        )

    if not scenarios:
        return

    lines = ["  These are realistic scenarios based on the actual capabilities Aegis found:\n"]
    for i, scenario in enumerate(scenarios, start=1):
        lines.append(f"  {i}. {_ascii_safe(scenario)}\n")

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines).rstrip(),
            border_style="dark_orange",
            title="[bold dark_orange]What Could Go Wrong[/bold dark_orange]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_recommendations(
    capabilities: dict[str, dict[str, list[str]]],
    restricted_findings: list[Finding],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict[str, Any]],
    external_binaries: list[str],
    denied_bins: list[str],
    unrecognized_bins: list[str],
    risk_score: int = 0,
) -> None:
    """Print clear, plain-English install checklist."""
    steps: list[str] = []

    if risk_score >= 50:
        steps.append(
            "[bold]Read the risky code paths first:[/bold] credential access, network calls, and subprocess execution."
        )

    wildcard_count = 0
    for cat_actions in capabilities.values():
        for scopes in cat_actions.values():
            if "*" in scopes:
                wildcard_count += 1
    if wildcard_count:
        steps.append(
            f"[bold]Resolve {wildcard_count} unresolved scope(s):[/bold] follow variables to learn exactly what files, hosts, or commands are targeted."
        )

    if risk_score >= 25:
        steps.append(
            "[bold]Verify who wrote this tool:[/bold] check repository history, maintenance activity, and community trust."
        )

    if "secret" in capabilities or "env" in capabilities:
        steps.append(
            "[bold]Audit secret usage:[/bold] confirm each secret is required for the task and is never copied to logs, files, or outbound requests."
        )

    if risk_score >= 50 or combination_risks:
        steps.append(
            "[bold]Test in a sandbox first:[/bold] run in a container/VM with fake credentials and monitor outbound traffic."
        )

    if path_violations:
        steps.append(
            f"[bold]Review {len(path_violations)} sensitive path access finding(s):[/bold] ensure access is essential and read-only where possible."
        )

    crit = [r for r in combination_risks if r.severity == "critical"]
    if crit:
        steps.append(
            f"[bold]Treat critical capability combinations seriously:[/bold] {len(crit)} combination(s) can enable harmful chained behavior."
        )

    if denied_bins:
        steps.append(
            f"[bold]Challenge denied binaries:[/bold] {', '.join(denied_bins)} are blocked by policy. Ask for a clear justification."
        )

    if unrecognized_bins:
        steps.append(
            f"[bold]Validate unknown binaries:[/bold] {', '.join(unrecognized_bins)} are not on your allow-list."
        )

    if risk_score >= 25:
        steps.append(
            "[bold]Pin to a specific commit or release:[/bold] avoid floating versions like latest."
        )

    # ── Always-show baseline tips ──
    # These are helpful regardless of risk level
    baseline = []
    if risk_score < 25 and not steps:
        baseline.append(
            "[bold]Pin to a specific version:[/bold] install from a tagged "
            "release or commit hash, not 'latest'."
        )
    baseline.append(
        "[bold]Check the developer's reputation:[/bold] look at their "
        "profile, other published skills, and community activity."
    )
    if risk_score < 25:
        baseline.append(
            "[bold]Read the SKILL.md:[/bold] confirm the skill does what you "
            "need and the documentation matches the code."
        )

    steps.extend(baseline)

    if not steps:
        _safe_print(
            Panel(
                f"  {ICON_PASS}  No issues found. Ready for certification.\n\n"
                "  Generate a signed lockfile with [white]aegis lock[/white], "
                "verify later with [white]aegis verify[/white].",
                border_style="green",
                title="[bold green]Ready to Install[/bold green]",
                expand=True,
                safe_box=True,
            )
        )
        return

    body = ""
    for i, step in enumerate(steps, 1):
        # steps contain rich markup ([bold]...) so don't _ascii_safe them
        body += f"  {i}.  {step}\n"

    _safe_print()
    _safe_print(
        Panel(
            body.rstrip(),
            border_style="yellow",
            title="[bold yellow]Before You Install[/bold yellow]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def _extract_implication(detail: str) -> str | None:
    """Extract the key 'so what?' sentence from a meta insight detail.

    Never truncates — the panel wraps naturally.
    """
    paragraphs = detail.strip().split("\n\n")
    if len(paragraphs) < 2:
        return None
    last_para = paragraphs[-1].strip().replace("\n", " ")
    # Take the first two sentences for a complete thought
    sentences = last_para.split(". ")
    if len(sentences) >= 2:
        return sentences[0].strip() + ". " + sentences[1].strip()
    return sentences[0].strip()


def print_meta_insights(insights: list[MetaInsight]) -> None:
    """Print trust analysis — SKILL.md vs actual code, one consolidated panel.

    This is Aegis's differentiator: cross-referencing documentation claims
    against what the code actually does. Each finding is a compact bullet,
    not a paragraph. Evidence is inline, not in a separate section.
    """
    if not insights:
        return

    has_danger = any(i.severity == MetaInsightSeverity.DANGER for i in insights)
    has_warning = any(
        i.severity == MetaInsightSeverity.WARNING for i in insights
    )

    if has_danger:
        border = "red"
    elif has_warning:
        border = "yellow"
    else:
        border = "green"

    body = "  Aegis cross-referenced SKILL.md against the actual code.\n"

    for insight in insights:
        if insight.severity == MetaInsightSeverity.PASS:
            icon = ICON_PASS
        elif insight.severity == MetaInsightSeverity.INFO:
            icon = ICON_INFO
        elif insight.severity == MetaInsightSeverity.WARNING:
            icon = ICON_WARN
        else:
            icon = ICON_DANGER

        body += f"\n  {icon}  {_ascii_safe(insight.summary)}\n"

        # Show key evidence for non-pass findings (compact bullets)
        if insight.evidence and insight.severity not in (
            MetaInsightSeverity.PASS,
        ):
            for ev in insight.evidence[:4]:
                body += f"     [dim]{_ascii_safe(ev)}[/dim]\n"
            remaining = len(insight.evidence) - 4
            if remaining > 0:
                body += f"     [dim]... and {remaining} more[/dim]\n"

        # For danger findings, surface the actionable implication
        if insight.severity == MetaInsightSeverity.DANGER and insight.detail:
            implication = _extract_implication(insight.detail)
            if implication:
                body += f"     [yellow]-> {_ascii_safe(implication)}[/yellow]\n"

    _safe_print()
    _safe_print(
        Panel(
            body.rstrip(),
            border_style=border,
            title=f"[bold {border}]Trust Analysis[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def _build_vibe_paragraph(
    *,
    persona_name: str,
    risk_score: int,
    reasoning: str,
    prohibited_count: int,
    combo_risk_count: int,
    denied_binary_count: int,
    path_violation_count: int,
    secret_finding_count: int,
    capability_categories: list[str],
    meta_insights: list[MetaInsight],
) -> str:
    """Build a single, human-readable paragraph that explains the vibe.

    This is the heart of the report. It should read like a curious, helpful
    colleague giving you a 10-second verbal summary. The tone is analytical:
    we explain what we found and what it likely means, not just scream danger.
    """
    danger_meta = sum(1 for i in meta_insights if i.severity == MetaInsightSeverity.DANGER)
    warning_meta = sum(1 for i in meta_insights if i.severity == MetaInsightSeverity.WARNING)

    # -- Start with the risk framing --
    if prohibited_count > 0:
        opener = (
            f"Aegis scored this skill {risk_score}/100. It contains code patterns "
            "like eval() or exec() that can run arbitrary code at runtime, which "
            "makes static analysis impossible. This is a hard block."
        )
    elif risk_score >= 75:
        opener = (
            f"Aegis scored this skill {risk_score}/100. "
            "That is high because the permissions it requests are broad relative "
            "to what the code and documentation justify."
        )
    elif risk_score >= 50:
        opener = (
            f"Aegis scored this skill {risk_score}/100. "
            "It requests some powerful permissions that may be perfectly "
            "legitimate for its purpose, but are worth understanding before "
            "you install."
        )
    elif risk_score >= 25:
        opener = (
            f"Aegis scored this skill {risk_score}/100. "
            "It uses a few sensitive APIs, but the scope looks reasonable "
            "for a tool of this type."
        )
    else:
        opener = (
            f"Aegis scored this skill {risk_score}/100. "
            "The code requests minimal permissions and nothing looks unusual."
        )

    # -- Add the most important observation (not alarm, observation) --
    observation = ""
    if combo_risk_count and risk_score >= 50:
        observation = (
            f" The most notable finding: {combo_risk_count} capability "
            "combination(s) where permissions reinforce each other in ways "
            "that could be misused."
        )
    elif denied_binary_count:
        observation = (
            f" It references {denied_binary_count} system tool(s) that "
            "are on the default deny list, which may be expected for a tool "
            "in this domain or may indicate unnecessary power."
        )
    elif path_violation_count:
        observation = (
            f" It references {path_violation_count} sensitive path(s). "
            "Check whether that access is necessary for the task."
        )

    # -- Documentation trust observations --
    trust_note = ""
    if danger_meta:
        trust_note = (
            " The documentation makes claims that don't align with what "
            "Aegis found in the actual code. This mismatch is the most "
            "important thing to investigate."
        )
    elif warning_meta > 1:
        trust_note = (
            " There are some discrepancies between the documentation and "
            "the code. See Trust Analysis below for details."
        )

    # -- Frame secrets in context --
    secret_note = ""
    if secret_finding_count > 10:
        secret_note = (
            f" Aegis flagged {secret_finding_count} strings that look like "
            "hardcoded secrets. In data-heavy codebases, most of these tend "
            "to be hash constants or dataset IDs. The specifics are in "
            "aegis_report.json."
        )
    elif secret_finding_count > 0:
        secret_note = (
            f" Aegis flagged {secret_finding_count} possible hardcoded "
            "secret(s). Review them in aegis_report.json to see if any are "
            "real credentials."
        )

    # -- Close with the persona reasoning --
    persona_close = ""
    if reasoning:
        persona_close = f" {_ascii_safe(reasoning)}"

    return opener + observation + trust_note + secret_note + persona_close


def print_vibe_check(
    risk_score: int,
    persona: PersonaClassification | None,
    prohibited_count: int,
    restricted_count: int,
    path_violation_count: int,
    combo_risk_count: int,
    denied_binary_count: int,
    unrecognized_binary_count: int,
    secret_finding_count: int,
    unresolved_scope_count: int,
    total_scope_count: int,
    capability_categories: list[str],
    static_risk: int = 0,
    llm_adj: int = 0,
    combination_risks: list[CombinationRisk] | None = None,
    path_violations: list[dict] | None = None,
    meta_insights: list[MetaInsight] | None = None,
    permission_overreach: list[str] | None = None,
) -> None:
    """Print the Vibe Check: 1 emoji, 1 persona name, 1 paragraph."""
    combination_risks = combination_risks or []
    path_violations = path_violations or []
    meta_insights = meta_insights or []
    permission_overreach = permission_overreach or []

    border = _risk_color(risk_score).replace("bold ", "")
    icon = _persona_icon(persona)

    persona_name = "Unknown"
    persona_tagline = ""
    reasoning = ""
    if persona:
        p_info = PERSONA_DISPLAY.get(persona.persona.value, {})
        persona_name = p_info.get(
            "name",
            persona.persona.value.replace("_", " ").title(),
        )
        persona_tagline = p_info.get("description", "") or p_info.get("tagline", "")
        reasoning = persona.reasoning

    paragraph = _build_vibe_paragraph(
        persona_name=persona_name,
        risk_score=risk_score,
        reasoning=reasoning,
        prohibited_count=prohibited_count,
        combo_risk_count=combo_risk_count,
        denied_binary_count=denied_binary_count,
        path_violation_count=path_violation_count,
        secret_finding_count=secret_finding_count,
        capability_categories=capability_categories,
        meta_insights=meta_insights,
    )

    level = _risk_level(risk_score)

    # Make the score meaning explicit
    if risk_score >= 75:
        score_label = "HIGH RISK - review carefully before installing"
    elif risk_score >= 50:
        score_label = "ELEVATED - some permissions need justification"
    elif risk_score >= 25:
        score_label = "MODERATE - a few things to check"
    elif risk_score >= 10:
        score_label = "LOW - minor observations only"
    else:
        score_label = "MINIMAL - very few permissions requested"

    bar = _risk_bar(risk_score)
    score_line = Text()
    score_line.append("  ")
    score_line.append_text(bar)
    score_line.append(f"  {risk_score}/100 - {score_label}")

    body_parts: list = [f"  {icon}  [bold]{_ascii_safe(persona_name)}[/bold]"]
    if persona_tagline:
        body_parts.append(f"  [dim]{_ascii_safe(persona_tagline)}[/dim]")
    body_parts.extend([
        "",
        score_line,
        "",
        f"  {_ascii_safe(paragraph)}",
    ])
    if permission_overreach:
        body_parts.extend([
            "",
            "  [dim]Taxonomy — worth double-checking:[/dim]",
            *[f"  [dim]• {_ascii_safe(msg)}[/dim]" for msg in permission_overreach],
        ])

    body = Group(*body_parts)

    _safe_print(
        Panel(
            body,
            border_style=border,
            title=f"[bold {border}]Vibe Check[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_report_card(
    risk_score: int,
    persona: PersonaClassification | None,
    prohibited_count: int,
    path_violation_count: int,
    combo_risk_count: int,
    denied_binary_count: int,
    unrecognized_binary_count: int,
    secret_finding_count: int,
    unresolved_scope_count: int,
    total_scope_count: int,
    capability_categories: list[str],
    static_risk: int = 0,
    llm_adj: int = 0,
    combination_risks: list[CombinationRisk] | None = None,
    path_violations: list[dict] | None = None,
) -> None:
    """Backward-compatible wrapper for older call sites/tests."""
    print_vibe_check(
        risk_score=risk_score,
        persona=persona,
        prohibited_count=prohibited_count,
        restricted_count=0,
        path_violation_count=path_violation_count,
        combo_risk_count=combo_risk_count,
        denied_binary_count=denied_binary_count,
        unrecognized_binary_count=unrecognized_binary_count,
        secret_finding_count=secret_finding_count,
        unresolved_scope_count=unresolved_scope_count,
        total_scope_count=total_scope_count,
        capability_categories=capability_categories,
        static_risk=static_risk,
        llm_adj=llm_adj,
        combination_risks=combination_risks,
        path_violations=path_violations,
    )


def print_persona_verdict(
    persona: PersonaClassification | None,
    risk_score: int,
    capabilities: dict[str, dict[str, list[str]]],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict],
) -> None:
    """No-op: verdict is now integrated into the Vibe Check card."""
    pass


def print_findings_table(
    restricted_findings: list[Finding],
    verbose: bool = False,
) -> None:
    """Print a plain-English findings summary."""
    if not restricted_findings:
        _safe_print(
            Panel(
                f"  {ICON_PASS}  Permissions: minimal. No high-risk API "
                "usage detected.",
                border_style="green",
                title="[bold green]Findings[/bold green]",
                title_align="left",
                expand=True,
                safe_box=True,
            )
        )
        return

    cat_counts: dict[str, int] = {}
    by_file: dict[str, int] = defaultdict(int)
    for f in restricted_findings:
        by_file[f.file] += 1
        if f.capability:
            cat = f.capability.category.value
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    top_files = sorted(by_file.items(), key=lambda x: (-x[1], x[0]))[:5]
    category_summary = ", ".join(
        f"{_ascii_safe(cat)}: {count}" for cat, count in sorted(cat_counts.items())
    )

    non_secret_count = len(restricted_findings) - cat_counts.get("secret", 0)
    secret_total = cat_counts.get("secret", 0)

    # Only mention non-secret categories in the headline
    non_secret_summary = ", ".join(
        f"{_ascii_safe(cat)}: {count}"
        for cat, count in sorted(cat_counts.items())
        if cat != "secret"
    )

    lines: list[str] = []
    if non_secret_count:
        lines.append(
            f"  Found {non_secret_count} capability-related finding(s) in {len(by_file)} file(s)."
        )
        if non_secret_summary:
            lines.append(f"  Categories: {non_secret_summary}")
    else:
        lines.append(f"  No dangerous capability findings. {len(by_file)} file(s) scanned.")

    if secret_total:
        lines.append("")
        lines.append(
            f"  Aegis also flagged {secret_total} string(s) that look like hardcoded secrets."
        )
        if secret_total > 10:
            lines.append(
                "  In data science and ML codebases, most of these are typically "
                "model hashes, dataset identifiers, or configuration constants "
                "rather than real passwords. Check aegis_report.json to see the "
                "actual values and decide which, if any, are real credentials."
            )
        else:
            lines.append(
                "  These could be real API keys, or they could be hash constants "
                "and configuration values. Check aegis_report.json to review each one."
            )

    lines.append("")
    lines.append("  Full technical details are in aegis_report.json.")

    if top_files:
        lines.append("")
        lines.append("  Files with the most findings:")
        for file_name, count in top_files:
            lines.append(f"    - {_ascii_safe(file_name)} ({count})")

    # Color based on non-secret findings (secrets are noisy, don't drive the color)
    if non_secret_count >= 10:
        border = "dark_orange"
    elif non_secret_count >= 1:
        border = "yellow"
    else:
        border = "green"

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines),
            border_style=border,
            title=f"[bold {border}]Findings Summary[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_remediation_feedback(feedback: dict[str, Any] | None) -> None:
    """Print machine-generated one-pass remediation tasks in human form."""
    if not feedback:
        return

    tasks = feedback.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        return

    lines: list[str] = []
    lines.append("  Prioritized fixes from the one-pass remediation planner:")

    shown = 0
    for task in tasks:
        if shown >= 6:
            break
        if not isinstance(task, dict):
            continue

        kind = str(task.get("kind", "finding"))
        if kind == "finding":
            file_name = _ascii_safe(str(task.get("file", "?")))
            line = task.get("line", 0)
            pattern = _ascii_safe(str(task.get("pattern", "")))
            fix = _ascii_safe(str(task.get("suggested_fix", ""))).strip()
            message = _ascii_safe(str(task.get("message", ""))).strip()
            lines.append(f"  {shown + 1}. [white]{file_name}:{line}[/white] — [yellow]{pattern}[/yellow]")
            if fix:
                lines.append(f"     do this: {fix}")
            elif message:
                lines.append(f"     why: {message}")
            shown += 1
        elif kind == "combination_risk":
            rule_id = _ascii_safe(str(task.get("rule_id", "combination_risk")))
            fix = _ascii_safe(str(task.get("suggested_fix", ""))).strip()
            lines.append(f"  {shown + 1}. [white]{rule_id}[/white] — dangerous capability combo")
            if fix:
                lines.append(f"     do this: {fix}")
            shown += 1

    if len(tasks) > shown:
        lines.append("")
        lines.append(
            f"  [dim]Showing top {shown} of {len(tasks)} remediation tasks. "
            "See aegis_report.json for the full machine-readable plan.[/dim]"
        )

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines),
            border_style="cyan",
            title="[bold cyan]Recommended Fixes[/bold cyan]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_capability_inventory(
    capabilities: dict[str, dict[str, list[str]]],
) -> None:
    """Print actionable capability review as a Panel (consistent with rest of report).

    When capabilities is empty: show attestation — "Permissions: minimal."
    When capabilities exist: show full inventory.
    """
    if not capabilities:
        _safe_print()
        _safe_print(
            Panel(
                "  Permissions: minimal. No high-risk APIs (network, subprocess, "
                "credentials) detected. See aegis_report.json.",
                border_style="green",
                title="[bold green]Capabilities[/bold green]",
                title_align="left",
                expand=True,
                safe_box=True,
            )
        )
        return

    cap_count = len(capabilities)
    lines: list[str] = []

    for category, actions in sorted(capabilities.items()):
        action_names = sorted(actions.keys())
        merged_scopes: list[str] = []
        unresolved = False
        for scopes in actions.values():
            merged_scopes.extend(scopes)
            if "*" in scopes:
                unresolved = True

        scope_preview = _compact_scope_text(merged_scopes, unresolved=unresolved)
        verb_map = ACTION_VERBS.get(category, {})
        verbs = [verb_map.get(a, a) for a in action_names]

        lines.append(
            f"  [bold]{_ascii_safe(category.upper())}[/bold]: "
            f"can {', '.join(_ascii_safe(v) for v in verbs)}"
        )
        lines.append(
            f"    Scope: {_ascii_safe(scope_preview)}"
        )
        if unresolved:
            lines.append(
                "    [yellow]Action: follow the code path to resolve the wildcard target "
                "and confirm this scope is reasonable.[/yellow]"
            )
        else:
            lines.append(
                "    [dim]Action: confirm these targets are necessary for the task.[/dim]"
            )
        lines.append("")

    # determine border by severity
    has_wildcards = any(
        "*" in s for acts in capabilities.values() for ss in acts.values() for s in ss
    )
    high_risk_cats = {"subprocess", "browser", "secret", "serial"}
    has_high = bool(high_risk_cats & set(capabilities.keys()))
    if has_high and has_wildcards:
        border = "dark_orange"
    elif has_high or has_wildcards:
        border = "yellow"
    else:
        border = "green"

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines).rstrip(),
            border_style=border,
            title=f"[bold {border}]Capabilities ({cap_count})[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_combination_risks_compact(risks: list[CombinationRisk]) -> None:
    """Print full combination risk summaries. Always runs in verbose; shows attestation when empty."""
    lines: list[str] = []

    if not risks:
        lines.append("  No dangerous capability combinations detected.")
    else:
        for idx, risk in enumerate(
            sorted(
                risks,
                key=lambda r: (r.severity != "critical", -r.risk_override, r.rule_id),
            ),
            start=1,
        ):
            lines.append(
                f"  {idx}. {_ascii_safe(risk.rule_id)} "
                f"({_ascii_safe(risk.severity.upper())}, score {risk.risk_override})"
            )
            lines.append(
                "     capabilities: "
                + ", ".join(_ascii_safe(c) for c in risk.matched_capabilities)
            )
            lines.append(f"     why this matters: {_ascii_safe(risk.message)}")
            if risk.suggested_fix:
                lines.append(f"     what to do: {_ascii_safe(risk.suggested_fix)}")

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines),
            border_style="dark_orange",
            title="[bold dark_orange]Combination Risks[/bold dark_orange]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_external_programs_compact(
    binaries: list[str],
    denied: list[str],
    unrecognized: list[str],
) -> None:
    """Print concise external program summary. Always runs in verbose; shows attestation when empty."""
    if not binaries:
        _safe_print()
        _safe_print(
            Panel(
                "  No external programs invoked.",
                border_style="green",
                title="[bold green]External Programs[/bold green]",
                title_align="left",
                expand=True,
                safe_box=True,
            )
        )
        return

    border = "red" if denied else ("yellow" if unrecognized else "green")
    lines = [
        "  Detected programs "
        f"({len(binaries)}): {', '.join(_ascii_safe(b) for b in sorted(binaries))}",
    ]
    if denied:
        lines.append(
            "  Denied by policy "
            f"({len(denied)}): {', '.join(_ascii_safe(b) for b in sorted(denied))}"
        )
    if unrecognized:
        lines.append(
            "  Unrecognized binaries "
            f"({len(unrecognized)}): "
            f"{', '.join(_ascii_safe(b) for b in sorted(unrecognized))}"
        )
    allowed = [b for b in binaries if b not in denied and b not in unrecognized]
    if allowed:
        lines.append(
            "  Allow-listed "
            f"({len(allowed)}): {', '.join(_ascii_safe(b) for b in sorted(allowed))}"
        )

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines),
            border_style=border,
            title=f"[bold {border}]External Programs[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_path_violations_compact(violations: list[dict[str, Any]]) -> None:
    """Print concise path-violation summary. Always runs in verbose; shows attestation when empty."""
    if not violations:
        _safe_print()
        _safe_print(
            Panel(
                "  No sensitive path violations.",
                border_style="green",
                title="[bold green]Sensitive Path Violations[/bold green]",
                title_align="left",
                expand=True,
                safe_box=True,
            )
        )
        return

    table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="red",
        title="[bold red]Sensitive Path Violations[/bold red]",
        title_justify="left",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Capability", style="cyan", ratio=1, min_width=10, overflow="fold")
    table.add_column("Scope", style="white", ratio=2, min_width=12, overflow="fold")
    table.add_column("Matched Rule", style="yellow", ratio=1, min_width=10, overflow="fold")

    for violation in violations:
        table.add_row(
            _ascii_safe(violation.get("capability", "-")),
            _ascii_safe(violation.get("scope", "-")),
            _ascii_safe(violation.get("deny_pattern", "-")),
        )

    _safe_print()
    _safe_print(table)


def print_verbose_risk_briefs(
    capabilities: dict[str, dict[str, list[str]]],
    findings: list[Finding],
    external_binaries: list[str],
    denied_bins: list[str],
    unrecognized_bins: list[str],
    combination_risks: list[CombinationRisk],
) -> None:
    """Concise risk briefs for high-impact categories (--verbose only).

    Attestation model: Always show four pillars. When a category has no findings,
    show "None detected." so compliance officers get full attestation.
    """
    lines: list[str] = []

    secret_count = sum(
        1 for f in findings if f.capability and f.capability.category.value == "secret"
    )

    # Pillar 1: Credential & secret access — always shown
    lines.append("[bold]Credential & secret access[/bold]")
    if "secret" in capabilities or secret_count:
        if secret_count > 10:
            lines.append(
                f"  Aegis detected {secret_count} patterns that look like credential access. "
                "Many of these may be hash constants or config values, not real secrets."
            )
        elif secret_count > 0:
            lines.append(
                f"  Aegis detected {secret_count} pattern(s) related to credential access."
            )
        else:
            lines.append("  Credential-related capability present; review usage.")
        lines.append(
            "  Action: confirm each one is necessary and never sent to external services."
        )
    else:
        lines.append(
            "  None detected. No hardcoded secrets, credential-store access, or env-var reads found."
        )
    lines.append("")

    # Pillar 2: Program execution — always shown
    lines.append("[bold]Program execution[/bold]")
    if "subprocess" in capabilities:
        if external_binaries:
            lines.append(
                "  The code can run external programs: "
                + ", ".join(_ascii_safe(b) for b in sorted(external_binaries))
            )
        if denied_bins:
            lines.append(
                "  Policy denied program(s): "
                + ", ".join(_ascii_safe(b) for b in sorted(denied_bins))
            )
        if unrecognized_bins:
            lines.append(
                "  Unrecognized program(s): "
                + ", ".join(_ascii_safe(b) for b in sorted(unrecognized_bins))
            )
        lines.append(
            "  Action: verify commands are pinned, argument-safe, and truly needed."
        )
    else:
        lines.append(
            "  None detected. No subprocess, shell, or external binary invocations found."
        )
    lines.append("")

    # Pillar 3: System-level access — always shown
    lines.append("[bold]System-level access[/bold]")
    if "system" in capabilities:
        lines.append(
            "  The code reads machine/system information. This can be legitimate diagnostics or reconnaissance."
        )
        lines.append(
            "  Action: verify system access is required for the task and not combined with risky data movement."
        )
    else:
        lines.append(
            "  None detected. No platform/sysinfo calls or signal handlers found."
        )
    lines.append("")

    # Pillar 4: Supply chain risk — always shown
    supply_chain = [r for r in combination_risks if "supply-chain" in r.rule_id]
    has_subprocess_and_unrec = "subprocess" in capabilities and unrecognized_bins
    if supply_chain or has_subprocess_and_unrec:
        lines.append("[bold]Supply chain risk[/bold]")
        if supply_chain:
            for risk in supply_chain:
                lines.append(f"  {_ascii_safe(risk.message)}")
        if has_subprocess_and_unrec:
            lines.append(
                "  Subprocess + unrecognized binaries: review each binary, pin versions."
            )
        lines.append(
            "  Action: review each binary/dependency, pin versions, and use trusted sources."
        )
    else:
        lines.append("[bold]Supply chain risk[/bold]")
        lines.append(
            "  None detected. No combination of subprocess + unrecognized binaries."
        )
    lines.append("")

    # One-line "What could go wrong" tie-in when relevant combos exist
    critical_high = [
        r for r in combination_risks
        if r.severity in ("critical", "high")
    ]
    if critical_high:
        for risk in critical_high[:3]:  # Max 3 to keep brief compact
            caps = " + ".join(risk.matched_capabilities)
            lines.append(
                f"  [dim]Risky combo: {_ascii_safe(caps)}. See aegis_report.json.[/dim]"
            )

    _safe_print()
    _safe_print(
        Panel(
            "\n".join(lines).rstrip(),
            border_style="dark_orange",
            title="[bold dark_orange]Verbose Risk Briefs[/bold dark_orange]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_restricted_findings(findings: list[Finding], verbose: bool = False) -> None:
    """Legacy: Print restricted findings table (verbose only).

    Kept for backward compatibility. The new print_findings_table is preferred.
    """
    if not findings or not verbose:
        return

    _safe_print("\n[bold dim]Detailed Findings (--verbose):[/bold dim]")

    table = Table(
        show_header=True,
        header_style="bold yellow",
        border_style="dim",
        expand=True,
    )
    table.add_column("File", style="white", ratio=2, min_width=8, overflow="fold")
    table.add_column("Line", style="dim", justify="right", min_width=4)
    table.add_column("Pattern", style="yellow", ratio=1, min_width=8, overflow="fold")
    table.add_column("Capability", style="cyan", ratio=1, min_width=10, overflow="fold")
    table.add_column("Scope", style="green", ratio=2, min_width=8, overflow="fold")
    table.add_column("Resolved", style="dim", justify="center", min_width=8)
    table.add_column("Fix", style="cyan", ratio=1, min_width=8, overflow="fold")

    for f in findings:
        cap_str = f.capability.capability_key if f.capability else "-"
        scope_str = ", ".join(f.capability.scope) if f.capability else "-"
        resolved = "yes" if f.capability and f.capability.scope_resolved else "no"
        scope_style = "green" if resolved == "yes" else "yellow"
        fix_str = f.suggested_fix or "-"
        table.add_row(
            f.file,
            str(f.line),
            f.pattern,
            cap_str,
            Text(scope_str, style=scope_style),
            resolved,
            fix_str,
        )

    _safe_print(table)


def print_llm_analysis(analysis: str | None, verbose: bool = False) -> None:
    """Print LLM analysis panel."""
    if not analysis or not verbose:
        return

    _safe_print(
        Panel(
            analysis,
            border_style="blue",
            title="[bold blue]AI Analysis[/bold blue]",
            expand=True,
            safe_box=True,
        )
    )


def print_summary(
    report_path: str | None = None,
    lockfile_path: str | None = None,
    hard_fail: bool = False,
    is_lock_command: bool = False,
) -> None:
    """Print summary footer with output file paths."""
    _safe_print()

    if hard_fail:
        _safe_print(
            Panel(
                f"  [bold red]CERTIFICATION BLOCKED[/bold red]\n\n"
                "  Prohibited patterns were detected. A lockfile was NOT generated.\n"
                "  This skill cannot be certified until all prohibited code patterns "
                "are removed.\n\n"
                "  [dim]Run with --verbose to see full technical details for each "
                "finding.[/dim]",
                border_style="red",
                title="[bold red]Result[/bold red]",
                expand=True,
                safe_box=True,
            )
        )
        return

    parts = []
    if report_path:
        parts.append(f"  Report:   [white]{_ascii_safe(report_path)}[/white]")
    if lockfile_path:
        parts.append(f"  Lockfile: [white]{_ascii_safe(lockfile_path)}[/white]")
        parts.append("")
        parts.append(
            f"  {ICON_PASS}  [green]Lockfile generated.[/green] "
            "This skill is cryptographically signed and ready for deployment."
        )
        parts.append(
            "  [dim]Run [white]aegis verify[/white] at any time to "
            "confirm the code hasn't been tampered with.[/dim]"
        )
    elif is_lock_command:
        parts.append(
            f"  {ICON_WARN}  [yellow]Lockfile NOT generated.[/yellow] "
            "Risk is too high for automatic certification."
        )
        parts.append(
            "  [dim]Use [white]--force[/white] to override if you've reviewed "
            "the findings and accept the risk.[/dim]"
        )
    else:
        parts.append(
            "  [dim]This was a read-only scan. Run [white]aegis lock[/white] "
            "to generate a signed lockfile.[/dim]"
        )

    border = "green" if lockfile_path else ("yellow" if is_lock_command else "dim")
    _safe_print(
        Panel(
            "\n".join(parts),
            border_style=border,
            title=f"[bold {border}]Scan Complete[/bold {border}]",
            title_align="left",
            expand=True,
            safe_box=True,
        )
    )


def print_verify_result(passed: bool, details: str = "") -> None:
    """Print verification result."""
    if passed:
        body = (
            f"  {ICON_PASS}  [bold green]VERIFICATION PASSED[/bold green]\n\n"
            "  Every file matches the cryptographic hashes in the signed "
            "lockfile. No code has been modified since certification."
        )
        if details:
            body += f"\n\n  {details}"
        _safe_print(
            Panel(
                body,
                border_style="green",
                title="[bold green]aegis verify[/bold green]",
                expand=True,
                safe_box=True,
            )
        )
    else:
        body = (
            f"  {ICON_DANGER}  [bold red]VERIFICATION FAILED[/bold red]\n\n"
            "  The code has changed since the lockfile was signed. The skill "
            "may have been tampered with or updated without re-certification."
        )
        if details:
            body += f"\n\n  {details}"
        body += (
            "\n\n  [dim]Run [white]aegis scan[/white] to re-audit and generate "
            "a new lockfile for the current code.[/dim]"
        )
        body += (
            "\n  [dim]If this change is unexpected, follow [white]docs/INCIDENT_RESPONSE.md[/white] "
            "and record the event in [white]docs/RISK_REGISTER.md[/white].[/dim]"
        )
        _safe_print(
            Panel(
                body,
                border_style="red",
                title="[bold red]aegis verify[/bold red]",
                expand=True,
                safe_box=True,
            )
        )


def print_full_report(
    report: ScanReport,
    verbose: bool = False,
    report_path: str | None = None,
    lockfile_path: str | None = None,
    python_count: int = 0,
    shell_count: int = 0,
    js_count: int = 0,
    config_count: int = 0,
    docker_count: int = 0,
    denied_bins: list[str] | None = None,
    unrecognized_bins: list[str] | None = None,
    is_lock_command: bool = False,
    permission_overreach: list[str] | None = None,
) -> None:
    """Print the complete scan report."""
    det = report.deterministic
    eph = report.ephemeral
    denied_bins = denied_bins or []
    unrecognized_bins = unrecognized_bins or []
    scan_mode = "AST-only" if not eph.llm_provider else f"AST + LLM ({eph.llm_provider})"

    # 1. Header
    print_scan_header(
        report.scan_target,
        det.file_count,
        det.manifest_source,
        python_count=python_count,
        shell_count=shell_count,
        js_count=js_count,
        config_count=config_count,
        docker_count=docker_count,
        scan_mode=scan_mode,
    )

    # 2. Prohibited findings (hard block)
    hard_fail = len(det.prohibited_findings) > 0
    if hard_fail:
        print_prohibited_findings(det.prohibited_findings)

    # 3. Risk overview
    risk = det.risk_score_static
    final = eph.risk_score_final if eph.risk_score_final else risk

    secret_count = sum(
        1 for f in det.restricted_findings
        if f.capability and f.capability.category.value == "secret"
    )

    unresolved = sum(
        1 for f in det.restricted_findings
        if f.capability and not f.capability.scope_resolved
    )
    total_scoped = sum(
        1 for f in det.restricted_findings
        if f.capability
    )

    print_vibe_check(
        risk_score=final,
        persona=det.persona,
        prohibited_count=len(det.prohibited_findings),
        restricted_count=len(det.restricted_findings),
        path_violation_count=len(det.path_violations),
        combo_risk_count=len(det.combination_risks),
        denied_binary_count=len(denied_bins),
        unrecognized_binary_count=len(unrecognized_bins),
        secret_finding_count=secret_count,
        unresolved_scope_count=unresolved,
        total_scope_count=total_scoped,
        capability_categories=list(det.capabilities.keys()),
        static_risk=risk,
        llm_adj=eph.llm_risk_adjustment,
        combination_risks=det.combination_risks,
        path_violations=det.path_violations,
        meta_insights=det.meta_insights,
        permission_overreach=permission_overreach or [],
    )

    # Trust analysis should always be visible (code vs docs consistency)
    if det.meta_insights:
        print_meta_insights(det.meta_insights)

    if hard_fail:
        print_summary(report_path=None, lockfile_path=None, hard_fail=True)
        return

    # 4. AI analysis (if available)
    if eph.llm_analysis:
        # Indent every line so multi-paragraph output aligns consistently
        ai_lines = eph.llm_analysis.split("\n")
        ai_indented = "\n".join(
            "  " + line if line.strip() else ""
            for line in ai_lines
        )
        _safe_print(
            Panel(
                ai_indented,
                border_style="blue",
                title="[bold blue]AI Analysis[/bold blue]",
                expand=True,
                safe_box=True,
            )
        )

    # 5. Findings and capability inventory
    print_findings_table(det.restricted_findings, verbose=verbose)
    print_remediation_feedback(det.remediation_feedback)
    print_capability_inventory(det.capabilities)
    print_what_could_go_wrong_compact(
        det.capabilities, denied_bins,
        combination_risks=det.combination_risks,
        path_violations=det.path_violations,
    )

    # 6. Before You Install — show in both normal and verbose
    print_recommendations(
        det.capabilities,
        det.restricted_findings,
        det.combination_risks,
        det.path_violations,
        det.external_binaries,
        denied_bins,
        unrecognized_bins,
        risk_score=final,
    )

    # 7. Verbose-only context panels (full attestation)
    if verbose:
        print_verbose_risk_briefs(
            det.capabilities,
            det.restricted_findings,
            det.external_binaries,
            denied_bins,
            unrecognized_bins,
            det.combination_risks,
        )
        print_combination_risks_compact(det.combination_risks)
        print_external_programs_compact(
            det.external_binaries, denied_bins, unrecognized_bins
        )
        print_path_violations_compact(det.path_violations)

    # 8. Summary
    print_summary(
        report_path=report_path,
        lockfile_path=lockfile_path,
        hard_fail=False,
        is_lock_command=is_lock_command,
    )
