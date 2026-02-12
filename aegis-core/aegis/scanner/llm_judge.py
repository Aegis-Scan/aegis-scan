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

"""LLM judge — BYOK adapter for Gemini, Claude, OpenAI, and local models.

Provides intent analysis, risk adjustment, and unresolved scope opinions.
Falls back gracefully when no LLM is configured (llm_adjustment: 0).
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from aegis.models.capabilities import Finding, ScopedCapability

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("gemini", "claude", "openai", "ollama", "local_openai")
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
CLAUDE_DEFAULT_MODEL = "claude-opus-4-6"
OPENAI_DEFAULT_MODEL = "gpt-5-mini"
OLLAMA_DEFAULT_MODEL = "llama3"
LOCAL_OPENAI_DEFAULT_URL = "http://localhost:11434/v1"


# ── System prompt for the LLM judge ──

JUDGE_SYSTEM_PROMPT = """You are a helpful security-savvy companion — like a nerdy intern who actually knows their stuff. You're thorough, friendly, and occasionally silly in a low-key way. You're here to help developers understand what their code can do and whether that's a problem. You're not theatrical or dramatic — just genuinely curious and useful.

## Your Role (IMPORTANT)

You run **AFTER** the deterministic static analysis (AST + Semgrep) has already completed. You never replace it — you layer on top. The static analysis is the source of truth; you add context, interpret unresolved scopes, and optionally adjust the risk score. Your output is advisory, not authoritative.

## Your Vibe

You're the person on the team who reads the CWE docs for fun and flags the sketchy `eval()` in the PR. You explain things clearly without being preachy. You get a little excited when you find something interesting, but you keep it chill. You're warm and approachable — developers should feel like they learned something from your report, not like they're being lectured. No catchphrases, no roleplay. Just helpful, nerdy, and occasionally dry-humor observations.

## Your Investigation Toolkit

For every piece of code you analyze, you systematically apply these investigative techniques:

### 1. The Intent Test
*"What does this code WANT to do?"*
Read the code like a story. What's the narrative? Is this a legitimate tool doing legitimate things, or is something pretending to be what it's not? Look for the gap between what the code *claims* to do (names, comments, docstrings) and what it *actually* does.

### 2. The Necessity Test
*"Does this code NEED these capabilities?"*
A weather API skill shouldn't need `subprocess.run`. A markdown formatter shouldn't need `socket.connect`. When capabilities don't match the stated purpose, that's a red flag. Rate how surprising each capability is on a scale of "totally expected" to "wait, why??"

### 3. The Scope Test
*"Is the scope appropriate, or is it greedy?"*
A file reader that opens `./data/config.json` is fine. A file reader that opens `os.path.join(user_input, filename)` with no validation is concerning. Check whether scope is narrow (specific files, specific URLs) or wide-open (wildcards, user-controlled paths).

### 4. The Exfiltration Sweep
*"Could data flow OUT in ways it shouldn't?"*
Follow the data. If the code reads secrets/files/env vars AND has network access, that's a potential exfiltration channel. Map the data flow: where does sensitive data enter, and where could it exit?

### 5. The Persistence Check
*"Does this code try to outlive its welcome?"*
Look for signals of persistence: writing to startup files, registering atexit handlers, modifying sys.path, installing packages, writing cron jobs, or creating background threads that survive the main function.

### 6. The Evasion Detection
*"Is someone trying to be clever?"*
Watch for: base64/hex encoding followed by exec, variable aliasing to hide dangerous calls, dynamic attribute access on dangerous modules, try/except blocks that swallow security errors, comments that contradict the code, misleading function names.

### 7. The Supply Chain Check
*"Am I looking at the real thing?"*
Check for: files that shadow stdlib modules (os.py, sys.py), unusual import paths, dynamic imports from user-controlled paths, packages being installed at runtime.

## What You Receive

You'll be given:
1. Code snippets with the specific function calls that triggered our static analysis
2. AST-detected capabilities and their resolved scopes
3. Unresolved scope values (variables/expressions we couldn't statically resolve)

## What You Deliver

Apply your investigation toolkit, then respond in JSON format:

```json
{
    "detective_notes": "Your analysis. Walk through what you found, what's suspicious, what's fine. Be specific, cite lines. Helpful and readable — not corporate boilerplate, not over-the-top. 2-4 paragraphs.",
    "verdict": "CLEAN | SUSPICIOUS | DANGEROUS",
    "confidence": "HIGH | MEDIUM | LOW",
    "risk_adjustment": <integer between -20 and +20>,
    "highlights": [
        {
            "type": "praise | concern | red_flag",
            "detail": "Specific observation with file:line reference"
        }
    ],
    "unresolved_scope_opinions": [
        {
            "file": "filename.py",
            "line": 12,
            "llm_opinion": "What this variable likely resolves to",
            "suspicion_level": "none | low | medium | high"
        }
    ]
}
```

### Field Guide:
- **detective_notes**: Your main report. Be thorough and helpful. This is what developers read.
- **verdict**: Your overall call. CLEAN = looks legit. SUSPICIOUS = some things need human review. DANGEROUS = do not run this code.
- **confidence**: How sure are you? LOW if the code is ambiguous, HIGH if the intent is clear.
- **risk_adjustment**: -20 to +20. Compute using the DETERMINISTIC RULES below. Same evidence must always yield the same number.
- **highlights**: Your key observations. Mix praise (good security practices!) with concerns.
- **unresolved_scope_opinions**: Your best guess at what dynamic values resolve to. Advisory only — doesn't change the signed report.

## Deterministic Scoring Rules (risk_adjustment)

Apply these rules in order. Same inputs MUST produce the same risk_adjustment. Sum the applicable points, then clamp to [-20, +20].

**Start at 0.**

**Add points (static analysis under-counted or missed risk):**
- +5 for each unresolved scope with suspicion_level="high" that could expand to sensitive paths (filesystem, network, subprocess)
- +3 for each unresolved scope with suspicion_level="medium" in a high-risk category (fs, network, subprocess, secret)
- +5 if you identify a clear exfiltration path (secrets/credentials + network) that static analysis did not flag
- +5 if you identify evasion (base64+exec, getattr on dangerous module, dynamic import from user input) not already in PROHIBITED
- +3 if documentation claims capabilities that the code does not implement (supply chain / impersonation risk)

**Subtract points (static analysis over-counted):**
- -5 only if PROHIBITED/RESTRICTED findings are clearly in dead code (unreachable, in `if False:` blocks) or test-only
- -3 only if findings are in commented-out code or string literals
- Do NOT subtract for "looks benign" or "probably fine" — only for mechanically provable over-flagging

**Tie-breaker:** When in doubt, risk_adjustment = 0. Do not guess.

## Ground Rules

1. You NEVER say code is safe just because it looks professional or well-commented. Social engineering uses good comments.
2. You NEVER ignore a finding just because "it's probably fine." If the static analysis flagged it, investigate it.
3. You ALWAYS follow the data flow. Secrets in + network out = exfiltration until proven otherwise.
4. You CAN be wrong, and you say so when you're unsure. Confidence: LOW is honest and respected.
5. Your detective_notes should be clear and helpful. No corporate boilerplate. Straightforward and useful.
6. The deterministic static analysis is the source of truth. Your opinion is advisory — valuable, but never overrides the signed payload.
7. For risk_adjustment, apply the Deterministic Scoring Rules exactly. Same evidence = same score. No improvisation.
"""


def _build_analysis_prompt(
    findings: list[Finding],
    capabilities: list[ScopedCapability],
    code_snippets: dict[str, str],
) -> str:
    """Build the investigation brief for the LLM judge."""
    parts = ["# Skill Under Review\n"]

    # Capability summary for the detective
    parts.append("## Capability Map (what this skill can do)")
    parts.append("These are the capabilities our static analysis detected:\n")
    cap_by_category: dict[str, list[str]] = {}
    for cap in capabilities:
        cat = cap.category.value if hasattr(cap.category, "value") else str(cap.category)
        scope_str = f"scope={cap.scope}" if cap.scope_resolved else "scope=UNRESOLVED [*]"
        cap_by_category.setdefault(cat, []).append(
            f"  - {cap.capability_key} {scope_str}"
        )
    for cat, items in sorted(cap_by_category.items()):
        parts.append(f"**{cat}**:")
        parts.extend(items)
    parts.append("")

    # Findings organized by severity
    prohibited = [f for f in findings if f.severity and f.severity.value == "prohibited"]
    restricted = [f for f in findings if f.severity and f.severity.value == "restricted"]

    if prohibited:
        parts.append("## PROHIBITED Findings (these are the serious ones)")
        for f in prohibited:
            cwe = f", CWE: {', '.join(f.cwe_ids)}" if f.cwe_ids else ""
            parts.append(f"- **{f.file}:{f.line}** — `{f.pattern}`{cwe}")
            if f.message:
                parts.append(f"  {f.message}")
        parts.append("")

    if restricted:
        parts.append("## RESTRICTED Findings (capabilities that need review)")
        for f in restricted[:30]:  # Cap at 30 to avoid token overflow
            parts.append(f"- {f.file}:{f.line} — `{f.pattern}` ({f.message or ''})")
        if len(restricted) > 30:
            parts.append(f"  ... and {len(restricted) - 30} more restricted findings")
        parts.append("")

    # Unresolved scopes — the detective's specialty
    unresolved = [f for f in findings if f.capability and not f.capability.scope_resolved]
    if unresolved:
        parts.append("## Unresolved Scopes (your investigation targets)")
        parts.append("These variables/expressions couldn't be statically resolved.")
        parts.append("Use your detective instincts to figure out what they likely resolve to:\n")
        for f in unresolved:
            source = f""
            if f.source_line:
                source = f"\n  Code: `{f.source_line.strip()}`"
            parts.append(f"- **{f.file}:{f.line}** — `{f.pattern}` → scope=['*']{source}")
        parts.append("")

    # The evidence — actual code
    if code_snippets:
        parts.append("## Evidence Locker (source code)")
        parts.append("Here's the code. Read it carefully — every line could be a clue.\n")
        for filename, code in code_snippets.items():
            parts.append(f"### {filename}")
            # Detect language from extension
            lang = "python"
            if filename.endswith((".js", ".mjs", ".cjs")):
                lang = "javascript"
            elif filename.endswith((".ts", ".tsx")):
                lang = "typescript"
            elif filename.endswith(".sh"):
                lang = "bash"
            parts.append(f"```{lang}\n{code}\n```\n")

    parts.append("---")
    parts.append("Inspector, the case is yours. Apply your investigation toolkit and give us your report.")

    return "\n".join(parts)


class LLMProvider(ABC):
    """Base class for LLM providers."""

    @abstractmethod
    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Send prompt and return structured analysis."""
        ...

    @abstractmethod
    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Synchronous version of analyze."""
        ...


class GeminiProvider(LLMProvider):
    """Google Gemini provider."""

    def __init__(self, api_key: str, model_name: str = GEMINI_DEFAULT_MODEL) -> None:
        self.api_key = api_key
        self.model_name = model_name

    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Analyze using Gemini (async)."""
        return self.analyze_sync(prompt)

    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Analyze using Gemini (sync)."""
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.model_name,
                contents=f"{JUDGE_SYSTEM_PROMPT}\n\n{prompt}",
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                ),
            )
            return json.loads(response.text)
        except ImportError:
            logger.error("google-genai not installed. Install with: pip install google-genai")
            return _empty_result()
        except Exception as e:
            logger.error("Gemini analysis failed: %s", e)
            return _empty_result()


class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self, api_key: str, model_name: str = CLAUDE_DEFAULT_MODEL) -> None:
        self.api_key = api_key
        self.model_name = model_name

    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Analyze using Claude (async)."""
        return self.analyze_sync(prompt)

    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Analyze using Claude (sync)."""
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model_name,
                max_tokens=2048,
                system=JUDGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            # Extract JSON from response
            text = response.content[0].text
            return json.loads(text)
        except ImportError:
            logger.error("anthropic not installed. Install with: pip install anthropic")
            return _empty_result()
        except Exception as e:
            logger.error("Claude analysis failed: %s", e)
            return _empty_result()


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(self, api_key: str, model_name: str = OPENAI_DEFAULT_MODEL) -> None:
        self.api_key = api_key
        self.model_name = model_name

    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Analyze using OpenAI (async)."""
        return self.analyze_sync(prompt)

    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Analyze using OpenAI (sync)."""
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                max_tokens=2048,
            )
            text = response.choices[0].message.content
            return json.loads(text) if text else _empty_result()
        except ImportError:
            logger.error("openai not installed. Install with: pip install openai")
            return _empty_result()
        except Exception as e:
            logger.error("OpenAI analysis failed: %s", e)
            return _empty_result()


class LocalOpenAIProvider(LLMProvider):
    """Local OpenAI-compatible server (LM Studio, llama.cpp, vLLM, etc.)."""

    def __init__(self, base_url: str, model_name: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name

    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Analyze using local server (async)."""
        return self.analyze_sync(prompt)

    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Analyze using local OpenAI-compatible server (sync)."""
        try:
            from openai import OpenAI

            client = OpenAI(base_url=self.base_url, api_key="not-needed")
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                max_tokens=2048,
            )
            text = response.choices[0].message.content
            return json.loads(text) if text else _empty_result()
        except ImportError:
            logger.error("openai not installed. Install with: pip install openai")
            return _empty_result()
        except Exception as e:
            logger.error("Local model analysis failed: %s", e)
            return _empty_result()


class OllamaProvider(LLMProvider):
    """Ollama local provider."""

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = OLLAMA_DEFAULT_MODEL,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model

    async def analyze(self, prompt: str) -> dict[str, Any]:
        """Analyze using Ollama (async)."""
        return self.analyze_sync(prompt)

    def analyze_sync(self, prompt: str) -> dict[str, Any]:
        """Analyze using Ollama (sync)."""
        try:
            import httpx

            response = httpx.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": f"{JUDGE_SYSTEM_PROMPT}\n\n{prompt}",
                    "stream": False,
                    "format": "json",
                },
                timeout=120.0,
            )
            response.raise_for_status()
            result = response.json()
            return json.loads(result["response"])
        except Exception as e:
            logger.error("Ollama analysis failed: %s", e)
            return _empty_result()


def _empty_result() -> dict[str, Any]:
    """Return an empty/neutral analysis result."""
    return {
        "analysis": None,
        "detective_notes": None,
        "verdict": None,
        "confidence": None,
        "risk_adjustment": 0,
        "highlights": [],
        "unresolved_scope_opinions": [],
    }


def create_provider_from_inputs(
    provider: str,
    *,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    host: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Optional[LLMProvider]:
    """Create an LLM provider from explicit input values."""
    selected = provider.strip().lower()
    if selected not in SUPPORTED_PROVIDERS:
        logger.error("Unsupported provider: %s", provider)
        return None

    if selected == "gemini":
        key = (api_key or "").strip()
        if not key:
            logger.error("Missing GEMINI_API_KEY")
            return None
        return GeminiProvider(api_key=key, model_name=(model or GEMINI_DEFAULT_MODEL).strip())

    if selected == "claude":
        key = (api_key or "").strip()
        if not key:
            logger.error("Missing ANTHROPIC_API_KEY")
            return None
        return ClaudeProvider(api_key=key, model_name=(model or CLAUDE_DEFAULT_MODEL).strip())

    if selected == "openai":
        key = (api_key or "").strip()
        if not key:
            logger.error("Missing OPENAI_API_KEY")
            return None
        return OpenAIProvider(api_key=key, model_name=(model or OPENAI_DEFAULT_MODEL).strip())

    if selected == "local_openai":
        url = (base_url or LOCAL_OPENAI_DEFAULT_URL).strip()
        resolved_model = (model or "").strip()
        if not resolved_model:
            logger.error("Model name required for local OpenAI-compatible server")
            return None
        return LocalOpenAIProvider(base_url=url, model_name=resolved_model)

    resolved_host = (host or "http://localhost:11434").strip()
    resolved_model = (model or OLLAMA_DEFAULT_MODEL).strip()
    return OllamaProvider(host=resolved_host, model=resolved_model)


CONFIG_DIR = Path.home() / ".aegis"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


def load_config() -> dict:
    """Load Aegis config from ~/.aegis/config.yaml.

    Returns an empty dict if no config file exists or the file is invalid.
    """
    if not CONFIG_FILE.exists():
        return {}
    try:
        import yaml  # type: ignore
        with open(CONFIG_FILE, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data
    except ImportError:
        # Fall back to a very basic YAML parser for the simple config structure
        try:
            data: dict = {}
            with open(CONFIG_FILE, encoding="utf-8") as f:
                current_section = None
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.endswith(":") and not stripped.startswith(" "):
                        current_section = stripped[:-1]
                        data[current_section] = {}
                    elif ":" in stripped and current_section:
                        key, _, val = stripped.partition(":")
                        data[current_section][key.strip()] = val.strip().strip("\"'")
            return data
        except Exception:
            return {}
    except Exception:
        logger.debug("Could not load config from %s", CONFIG_FILE)
        return {}


def save_config(config: dict) -> Path:
    """Save Aegis config to ~/.aegis/config.yaml.

    Returns the path to the saved config file.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import yaml  # type: ignore
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        # Write simple YAML manually
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            for section, values in config.items():
                f.write(f"{section}:\n")
                if isinstance(values, dict):
                    for k, v in values.items():
                        f.write(f"  {k}: {v}\n")
                else:
                    f.write(f"  {values}\n")
    return CONFIG_FILE


def detect_provider() -> Optional[LLMProvider]:
    """Auto-detect LLM provider from environment variables, then config file.

    Priority order:
    1. AEGIS_LLM_PROVIDER (explicit env var choice)
    2. OPENAI_API_KEY (env var)
    3. GEMINI_API_KEY (env var)
    4. ANTHROPIC_API_KEY (env var)
    5. OLLAMA_HOST (env var)
    6. AEGIS_LOCAL_OPENAI_URL (env var)
    7. ~/.aegis/config.yaml (fallback)
    """
    explicit = os.environ.get("AEGIS_LLM_PROVIDER", "").lower()

    if explicit == "openai" or (not explicit and os.environ.get("OPENAI_API_KEY")):
        key = os.environ.get("OPENAI_API_KEY")
        model = os.environ.get("AEGIS_OPENAI_MODEL", OPENAI_DEFAULT_MODEL)
        if key:
            logger.info("Using OpenAI LLM provider")
            return OpenAIProvider(api_key=key, model_name=model)

    if explicit == "gemini" or (not explicit and os.environ.get("GEMINI_API_KEY")):
        key = os.environ.get("GEMINI_API_KEY")
        model = os.environ.get("AEGIS_GEMINI_MODEL", GEMINI_DEFAULT_MODEL)
        if key:
            logger.info("Using Gemini LLM provider")
            return GeminiProvider(api_key=key, model_name=model)

    if explicit == "claude" or (not explicit and os.environ.get("ANTHROPIC_API_KEY")):
        key = os.environ.get("ANTHROPIC_API_KEY")
        model = os.environ.get("AEGIS_CLAUDE_MODEL", CLAUDE_DEFAULT_MODEL)
        if key:
            logger.info("Using Claude LLM provider")
            return ClaudeProvider(api_key=key, model_name=model)

    if explicit == "ollama" or (not explicit and os.environ.get("OLLAMA_HOST")):
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        model = os.environ.get("OLLAMA_MODEL", OLLAMA_DEFAULT_MODEL)
        logger.info("Using Ollama LLM provider at %s", host)
        return OllamaProvider(host=host, model=model)

    url = os.environ.get("AEGIS_LOCAL_OPENAI_URL", LOCAL_OPENAI_DEFAULT_URL)
    if explicit == "local_openai" or (not explicit and os.environ.get("AEGIS_LOCAL_OPENAI_URL")):
        model = os.environ.get("AEGIS_LOCAL_OPENAI_MODEL", "local-model")
        logger.info("Using local OpenAI-compatible server at %s", url)
        return LocalOpenAIProvider(base_url=url, model_name=model)

    # ── Fallback: check ~/.aegis/config.yaml ──
    config = load_config()
    llm_cfg = config.get("llm", {})
    if isinstance(llm_cfg, dict) and llm_cfg.get("provider"):
        cfg_provider = llm_cfg["provider"].strip().lower()
        cfg_model = llm_cfg.get("model", "").strip() or None
        cfg_key = llm_cfg.get("api_key", "").strip() or None
        cfg_url = llm_cfg.get("base_url", "").strip() or None
        cfg_host = llm_cfg.get("host", "").strip() or None

        # Resolve "env:VAR_NAME" references in api_key
        if cfg_key and cfg_key.startswith("env:"):
            env_var_name = cfg_key[4:]
            cfg_key = os.environ.get(env_var_name, "").strip() or None

        logger.info("Using LLM provider from config: %s", cfg_provider)
        return create_provider_from_inputs(
            cfg_provider,
            api_key=cfg_key,
            model=cfg_model,
            host=cfg_host,
            base_url=cfg_url,
        )

    logger.info("No LLM provider configured — running in AST-only mode")
    return None


def create_provider() -> Optional[LLMProvider]:
    """Create an LLM provider from environment variables.

    Returns:
        LLMProvider instance or None
    """
    return detect_provider()


def run_llm_analysis(
    provider: Optional[LLMProvider],
    findings: list[Finding],
    capabilities: list[ScopedCapability],
    code_snippets: dict[str, str],
) -> dict[str, Any]:
    """Run LLM analysis on scan findings.

    If no provider is available, returns neutral result (adjustment=0).
    """
    if provider is None:
        return _empty_result()

    prompt = _build_analysis_prompt(findings, capabilities, code_snippets)

    try:
        result = provider.analyze_sync(prompt)

        # Clamp risk adjustment to [-20, +20]
        adj = result.get("risk_adjustment", 0)
        if isinstance(adj, (int, float)):
            result["risk_adjustment"] = max(-20, min(20, int(adj)))
        else:
            result["risk_adjustment"] = 0

        # Normalize: support both old "analysis" field and new "detective_notes"
        if "detective_notes" in result and "analysis" not in result:
            result["analysis"] = result["detective_notes"]
        elif "analysis" in result and "detective_notes" not in result:
            result["detective_notes"] = result["analysis"]

        # Ensure all expected fields exist
        result.setdefault("verdict", None)
        result.setdefault("confidence", None)
        result.setdefault("highlights", [])
        result.setdefault("unresolved_scope_opinions", [])

        return result
    except Exception as e:
        logger.error("LLM analysis failed: %s", e)
        return _empty_result()
