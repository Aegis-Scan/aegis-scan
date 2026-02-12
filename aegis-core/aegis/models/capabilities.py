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

"""Pydantic models for scoped capabilities and findings."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CapabilityCategory(str, Enum):
    """Top-level capability categories."""

    FS = "fs"
    NETWORK = "network"
    SUBPROCESS = "subprocess"
    ENV = "env"
    BROWSER = "browser"
    SECRET = "secret"
    CRYPTO = "crypto"
    SERIAL = "serial"
    CONCURRENCY = "concurrency"
    SYSTEM = "system"


class CapabilityAction(str, Enum):
    """Actions within capability categories."""

    # fs
    READ = "read"
    WRITE = "write"
    DELETE = "delete"

    # network
    CONNECT = "connect"
    LISTEN = "listen"
    DNS = "dns"

    # subprocess
    EXEC = "exec"
    SPAWN = "spawn"

    # env
    # READ and WRITE reused

    # browser
    CONTROL = "control"
    NAVIGATE = "navigate"
    INJECT = "inject"

    # secret
    ACCESS = "access"
    STORE = "store"
    # DELETE reused

    # crypto
    SIGN = "sign"
    ENCRYPT = "encrypt"
    HASH = "hash"

    # serial
    DESERIALIZE = "deserialize"

    # concurrency
    THREAD = "thread"
    PROCESS = "process"
    ASYNC = "async"

    # system
    SIGNAL = "signal"
    SYSINFO = "sysinfo"


class ScopedCapability(BaseModel):
    """A capability with its extracted scope.

    Scope is PESSIMISTIC — only string literals and simple constant
    concatenations are resolved. Everything else yields scope=["*"].
    """

    category: CapabilityCategory
    action: CapabilityAction
    scope: list[str] = Field(default_factory=lambda: ["*"])
    scope_resolved: bool = False

    @property
    def capability_key(self) -> str:
        """Return the canonical capability key, e.g. 'fs:write'."""
        return f"{self.category.value}:{self.action.value}"

    def __hash__(self) -> int:
        return hash((self.category, self.action, tuple(self.scope)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScopedCapability):
            return NotImplemented
        return (
            self.category == other.category
            and self.action == other.action
            and self.scope == other.scope
        )


class FindingSeverity(str, Enum):
    """Severity level of a finding."""

    PROHIBITED = "prohibited"
    RESTRICTED = "restricted"


class Finding(BaseModel):
    """A single finding from the AST scanner.

    Core fields (always populated):
      file, line, pattern, severity, message

    Enrichment fields (populated by AST parser for richer reporting):
      source_line     — the actual code text at the finding location
      function_context — enclosing function/class, e.g. "MyClass.deploy"
      end_line/end_col — AST node range for agent-driven code modification
      cwe_ids         — CWE references, e.g. ["CWE-78"]
      owasp_ids       — OWASP Top 10 references, e.g. ["A03:2021"]
      risk_note       — one-line "why this matters HERE" explanation
      tags            — categorization labels for filtering/grouping
      confidence      — "high" (exact match), "medium" (heuristic), "low"
    """

    file: str
    line: int
    col: int = 0
    end_line: int = 0
    end_col: int = 0
    pattern: str  # e.g., "eval", "requests.get", "open"
    severity: FindingSeverity
    capability: Optional[ScopedCapability] = None
    message: str = ""
    suggested_fix: Optional[str] = None
    # ── Enrichment fields (all optional, backward-compatible) ──
    source_line: str = ""
    function_context: str = ""
    confidence: str = "high"
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_ids: list[str] = Field(default_factory=list)
    risk_note: str = ""
    tags: list[str] = Field(default_factory=list)


class CombinationRisk(BaseModel):
    """A triggered combination risk (trifecta)."""

    rule_id: str
    severity: str  # "critical", "high"
    matched_capabilities: list[str]
    risk_override: int
    message: str
    suggested_fix: Optional[str] = None


# ── Behavioral Persona System (The Vibe Check) ──


class PersonaType(str, Enum):
    """Behavioral persona archetypes assigned to scanned code.

    Each persona is a computed label derived from deterministic math:
    risk score, complexity, scope resolution, capability counts, and
    dependency analysis.  NOT an LLM opinion — pure math.
    """

    CRACKED_DEV = "cracked_dev"           # 10x engineer. Genius code.
    LGTM = "lgtm"                         # Awesome code. Just works.
    TRUST_ME_BRO = "trust_me_bro"         # Polished but shady.
    YOU_SURE_ABOUT_THAT = "you_sure_about_that"  # The Intern. Messy heart.
    CO_DEPENDENT_LOVER = "co_dependent_lover"    # The Supply Chain Risk.
    PERMISSION_GOBLIN = "permission_goblin"      # Over-scoped.
    SPAGHETTI_MONSTER = "spaghetti_monster"      # Unreadable chaos.
    THE_SNAKE = "the_snake"               # Clean but evil.


PERSONA_DISPLAY: dict[str, dict[str, str]] = {
    "cracked_dev": {
        "name": "Cracked Dev",
        "icon": "\U0001f525",  # 🔥
        "tagline": "I rewrote the kernel in my sleep.",
        "description": "10x engineer energy. Clean code, smart patterns, minimal permissions. The kind of skill you'd want to maintain.",
        "color": "bright_green",
        "suspicion": "NONE",
        "quote": "\"I rewrote the kernel in my sleep.\"",
    },
    "lgtm": {
        "name": "LGTM",
        "icon": "\u2705",  # ✅
        "tagline": "Awesome code. Just works.",
        "description": "Looks good to me. Permissions match the intent, scopes are sane, nothing weird. Ship it.",
        "color": "green",
        "suspicion": "LOW",
        "quote": "\"Ship it.\"",
    },
    "trust_me_bro": {
        "name": "Trust Me Bro",
        "icon": "\U0001f34c",  # 🍌
        "tagline": "Polished but shady.",
        "description": "Polished on the outside, suspicious on the inside. Docs vs code mismatch or unusual permissions. Trust, but verify.",
        "color": "yellow",
        "suspicion": "HIGH",
        "quote": "\"Source: Just trust me, bro.\"",
    },
    "you_sure_about_that": {
        "name": "You Sure About That?",
        "icon": "\U0001f914",  # 🤔
        "tagline": "The Intern. Messy but means well.",
        "description": "The intern special. Messy code, missing pieces, docs that overpromise. No malicious intent, but it needs a real review.",
        "color": "yellow",
        "suspicion": "MEDIUM",
        "quote": "\"It works on my machine.\"",
    },
    "co_dependent_lover": {
        "name": "Co-Dependent Lover",
        "icon": "\U0001f495",  # 💕
        "tagline": "Tiny logic, massive node_modules.",
        "description": "Tiny logic, huge dependency tree. Loves node_modules. Supply chain risk is real here.",
        "color": "yellow",
        "suspicion": "MEDIUM",
        "quote": "\"I can't live without my 200 dependencies.\"",
    },
    "permission_goblin": {
        "name": "Permission Goblin",
        "icon": "\U0001f47a",  # 👺
        "tagline": "Over-scoped. Asks for everything, uses nothing.",
        "description": "Wants everything: filesystem, network, secrets, the kitchen sink. Over-scoped and worth a closer look.",
        "color": "red",
        "suspicion": "HIGH",
        "quote": "\"I need Camera, Microphone, and your Social Security Number.\"",
    },
    "spaghetti_monster": {
        "name": "Spaghetti Monster",
        "icon": "\U0001f35d",  # 🍝
        "tagline": "Unreadable chaos. Impossible to audit.",
        "description": "Unreadable chaos. High complexity, hard to follow. Good luck auditing this.",
        "color": "red",
        "suspicion": "HIGH",
        "quote": "\"Good luck reading this.\"",
    },
    "the_snake": {
        "name": "The Snake",
        "icon": "\U0001f40d",  # 🐍
        "tagline": "Clean code. Evil intent.",
        "description": "Warning: This code might look clean, but it isn't. Do not use this skill, it is malicious by design.",
        "color": "bright_red",
        "suspicion": "CRITICAL",
        "quote": "\"I'm not here to make friends.\"",
    },
}


class PersonaClassification(BaseModel):
    """Result of persona classification for a scanned skill."""

    persona: PersonaType
    confidence: str = "high"  # "high" (deterministic match) or "moderate" (heuristic)
    reasoning: str = ""  # One-sentence explanation of why this persona was assigned
    suspicion: str = "LOW"  # NONE / LOW / MEDIUM / HIGH / CRITICAL


# ── Meta-analysis (SKILL.md / manifest cross-reference) ──


class MetaInsightSeverity(str, Enum):
    """Severity of a SKILL.md / manifest insight."""

    PASS = "pass"         # Everything checks out
    INFO = "info"         # Worth noting but not concerning
    WARNING = "warning"   # Mismatch or gap that deserves attention
    DANGER = "danger"     # Serious discrepancy — likely deceptive or broken


class MetaInsightCategory(str, Enum):
    """Categories for meta-analysis findings — mirrors OpenClaw's sections."""

    PURPOSE = "purpose"           # Claims vs. reality
    INSTRUCTION_SCOPE = "scope"   # Referenced files/commands that don't exist
    INSTALL_MECHANISM = "install" # How the skill installs and what runs
    CREDENTIALS = "credentials"   # Declared vs. actually-used credentials
    PERSISTENCE = "persistence"   # always: true, model-invocable, force-install
    TOOLS = "tools"               # Declared vs detected binaries


class MetaInsight(BaseModel):
    """A single meta-analysis finding from SKILL.md / manifest cross-reference.

    Unlike Finding (which comes from code analysis), MetaInsight captures
    discrepancies between what a skill *claims* and what it *provides*.
    """

    category: MetaInsightCategory
    severity: MetaInsightSeverity
    title: str          # e.g., "PURPOSE & CAPABILITY"
    summary: str        # One-sentence verdict
    detail: str         # Full plain-English explanation
    evidence: list[str] = Field(default_factory=list)  # Supporting data points
