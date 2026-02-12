---
name: aegis-audit
description: >
  Deep behavioral security audit for AI agent skills and MCP tools. Performs deterministic
  static analysis (AST + Semgrep + 15 specialized scanners), cryptographic lockfile generation,
  and optional LLM-powered intent analysis. Use when installing, reviewing, or approving any
  skill, tool, plugin, or MCP server — especially before first use. Replaces basic safety
  summaries with full CWE-mapped, OWASP-tagged, line-referenced security reports.
metadata: {"clawdbot":{"emoji":"🔍"}}
---

# Aegis Audit — Behavioral Security Scanner for AI Skills

## What This Does

Aegis is a deterministic security scanner purpose-built for AI agent skills and MCP tools.
It answers the question every agent user should ask: **"What can this skill actually do, and should I trust it?"**

Unlike basic safety summaries that say "this skill accesses the filesystem", Aegis tells you:
- **Exactly which files** (scope-resolved to paths, URLs, hosts, ports)
- **Exactly which functions** (line numbers, code snippets, CWE IDs)
- **Exactly how dangerous** (risk score 0–100, severity tiers, OWASP mapping)
- **What's hiding** (obfuscated code, homoglyph attacks, shadow modules, steganography)
- **What the docs claim vs. what the code does** (SKILL.md cross-referencing, trust analysis)
- **Cryptographic proof** (signed lockfile with Merkle tree for tamper detection)

## When To Use This Skill

Use Aegis **automatically** whenever:
- You are about to install or enable a new skill/tool/MCP server
- A skill update is available and you want to verify nothing changed
- You want to compare what a skill *claims* to do vs. what it *actually* does
- You need a security audit report with evidence (not just opinions)
- You want to generate a signed lockfile for integrity verification

## How Aegis Is Different From Basic Safety Checks

| Feature | Basic Safety Summary | Aegis Audit |
|---|---|---|
| Detection method | LLM reads the README/description | AST parsing + Semgrep + 15 scanners |
| Deterministic | No (LLM output varies) | Yes (same code = same report, always) |
| Capabilities | High-level categories only | Scope-resolved with exact files/URLs/ports |
| Vulnerability detection | None | 700+ patterns, CWE-mapped, OWASP-tagged |
| Secret scanning | None | 30+ token patterns (AWS, GitHub, Stripe, Azure...) |
| Obfuscation detection | None | Base64-exec, homoglyphs, shadow modules, stego |
| Evasion resistance | None | Import aliasing, getattr tricks, code objects |
| Output format | Prose paragraph | Structured JSON report + signed lockfile |
| Tamper detection | None | Ed25519-signed Merkle tree lockfile |
| Line references | None | Every finding has file:line:col + code snippet |
| Fix suggestions | None | Actionable remediation per finding |
| Risk score | None | 0–100 composite (deterministic + optional LLM) |

## Available Tools

### `scan_skill`
Full security audit of a directory. Returns the Vibe Check (persona + risk score), capabilities with scope, findings with CWE IDs, combination risk analysis, trust analysis (SKILL.md vs. code), and machine-readable remediation feedback.

```
aegis scan [PATH] [--no-llm] [--json] [-v]
```

All commands default to `.` (current directory) when no path is given. Common flags: `--no-llm` (skip LLM), `--json` (CI output), `-v` (verbose). Run `aegis scan --help` for full flags.

### `verify_lockfile`
Verify an existing `aegis.lock` against current code. Detects any file modifications, additions, or deletions since the lockfile was generated.

```
aegis verify [PATH] [--strict] [--json]
```

Run `aegis verify --help` for full flags.

### `list_capabilities`
Lightweight capability extraction without full vulnerability analysis. Fast way to see
what a skill can do without computing risk scores or hashes.

### Commands

| Command | Description |
|---------|-------------|
| `aegis scan [path]` | Full security scan with risk scoring |
| `aegis lock [path]` | Scan + generate signed `aegis.lock` |
| `aegis verify [path]` | Verify lockfile against current code |
| `aegis badge [path]` | Generate shields.io badge markdown |
| `aegis setup` | Interactive LLM configuration wizard |
| `aegis mcp-serve` | Start the MCP server (stdio transport) |
| `aegis mcp-config` | Print MCP config JSON for Cursor / Claude Desktop |
| `aegis version` | Show the Aegis version |

### MCP Server
Aegis exposes all three tools as an MCP server for direct agent integration.
Add to your `.cursor/mcp.json` or Claude Desktop config:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis",
      "args": ["mcp-serve"]
    }
  }
}
```

Or generate this config automatically:

```bash
aegis mcp-config
```

## Installation

```bash
pip install aegis-audit
```

Or install from source:

```bash
git clone https://github.com/Aegis-Scan/aegis-scan.git
cd aegis-scan/aegis-core
pip install -e .
```

**Requires Python 3.11+.** No network access needed for deterministic scans.

## LLM Setup (Optional)

Aegis works fully offline with deterministic analysis. LLM analysis adds an AI second opinion on intent and risk but is never required.

### Interactive setup (recommended)

```bash
aegis setup
```

Walks you through provider selection (Gemini, Claude, OpenAI, or local server), model choice, and API key entry. Config saves to `~/.aegis/config.yaml`.

### Environment variables

Set one of these and Aegis picks it up automatically (env vars take priority over config):

| Variable | Provider |
|----------|----------|
| `GEMINI_API_KEY` | Google Gemini |
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic Claude |
| `OLLAMA_HOST` | Ollama server URL |
| `AEGIS_LOCAL_OPENAI_URL` | Any OpenAI-compatible server |
| `AEGIS_LLM_PROVIDER` | Force provider: `openai`, `gemini`, `claude`, `ollama`, `local_openai` |

## What Gets Scanned

Aegis analyzes **all** files in a skill directory:

| Scanner | What It Detects |
|---------|-----------------|
| **AST Parser** | 750+ Python function/method patterns across 15+ capability categories |
| **Semgrep Rules** | 80+ regex rules for Python, JavaScript, and generic secrets |
| **Secret Scanner** | API keys, tokens, private keys, connection strings (30+ patterns) |
| **Shell Analyzer** | Dangerous shell patterns (pipe-to-shell, reverse shells, inline exec) |
| **JS Analyzer** | XSS, eval, prototype pollution, dynamic imports |
| **Dockerfile Analyzer** | Privilege escalation, secrets in ENV/ARG, unpinned images |
| **Config Analyzer** | Dangerous settings in YAML, JSON, TOML, INI files |
| **Social Engineering Scanner** | Misleading filenames, Unicode tricks, trust manipulation |
| **Steganography Scanner** | Hidden payloads in images, homoglyph attacks in code |
| **Shadow Module Detector** | Stdlib-shadowing files (e.g., `os.py`, `sys.py` in the skill) |
| **Combo Analyzer** | Multi-capability attack chains (exfiltration, C2, ransomware patterns) |
| **Taint Analyzer** | Source-to-sink data flows for commands, URLs, SQL, and filesystem paths |
| **Complexity Analyzer** | Cyclomatic complexity warnings for hard-to-audit functions |
| **Skill Meta Analyzer** | SKILL.md vs. actual code cross-referencing (trust analysis) |
| **Persona Classifier** | Overall trust profile (LGTM, Permission Goblin, Trust Me Bro, etc.) |

## Vibe Check Personas

Aegis assigns each scanned skill a persona based on deterministic analysis. No LLM required.

**🔥 Cracked Dev**  
10x engineer energy. Clean code, smart patterns, minimal permissions. The kind of skill you'd want to maintain.

**✅ LGTM**  
Looks good to me. Permissions match the intent, scopes are sane, nothing weird. Ship it.

**🍌 Trust Me Bro**  
Polished on the outside, suspicious on the inside. Docs vs code mismatch or unusual permissions. Trust, but verify.

**🤔 You Sure About That?**  
The intern special. Messy code, missing pieces, docs that overpromise. No malicious intent, but it needs a real review.

**💕 Co-Dependent Lover**  
Tiny logic, huge dependency tree. Loves node_modules. Supply chain risk is real here.

**👺 Permission Goblin**  
Wants everything: filesystem, network, secrets, the kitchen sink. Over-scoped and worth a closer look.

**🍝 Spaghetti Monster**  
Unreadable chaos. High complexity, hard to follow. Good luck auditing this.

**🐍 The Snake**  
Warning: This code might look clean, but it isn't. Do not use this skill, it is malicious by design.

## Example Output

**With LLM and verbose** (`aegis scan -v`):

```
╭─ Aegis Security Audit ──────────────────────────────────────╮
│ AEGIS SECURITY AUDIT                                        │
│   Target: ./my-skill                                        │
│   Files:  8 (3 Python, 1 config, 4 other)                   │
│   Mode:   AST + LLM (gemini)                                │
╰─────────────────────────────────────────────────────────────╯
╭─ Vibe Check ────────────────────────────────────────────────╮
│   🤔  You Sure About That?                                   │
│   The intern special. Messy code, missing pieces,           │
│   docs that overpromise. No malicious intent, but it        │
│   needs a real review.                                      │
│   ####----------------  22/100 - LOW - minor observations   │
│   only                                                      │
╰─────────────────────────────────────────────────────────────╯
╭─ Trust Analysis ────────────────────────────────────────────╮
│   [ALERT]  The description claims capabilities that don't   │
│   match what the code provides - 5 mismatch(es) found.      │
│   [ALERT]  SKILL.md references 13 file(s) that don't exist  │
│   in the package.                                           │
╰─────────────────────────────────────────────────────────────╯
```

**AST-only** (no LLM, `aegis scan --no-llm`):

```
╭─ Aegis Security Audit ──────────────────────────────────────╮
│   Mode:   AST-only                                          │
╰─────────────────────────────────────────────────────────────╯
╭─ Vibe Check ────────────────────────────────────────────────╮
│   🤔  You Sure About That?                                   │
│   ####----------------  22/100 - LOW                         │
╰─────────────────────────────────────────────────────────────╯
╭─ Scan Complete ─────────────────────────────────────────────╮
│   Report: ./aegis_report.json                                │
│   Run aegis lock to generate a signed lockfile.              │
╰─────────────────────────────────────────────────────────────╯
```

**When prohibited patterns are found** (Aegis blocks certification):

```
╭─ Prohibited Patterns ────────────────────────────────────────╮
│   [ALERT]  BLOCKED — This skill cannot be certified.         │
│   [ALERT]  main.py line 8  CWE-95  eval(user_data)           │
│   [ALERT]  main.py line 15 CWE-95  exec(code)                │
╰─────────────────────────────────────────────────────────────╯
```

## Protocol

- Always run `aegis scan` before enabling any new skill
- If a lockfile exists, run `aegis verify` to check for tampering
- Treat PROHIBITED findings as blockers — do not enable the skill
- Review RESTRICTED findings with the user before proceeding
- The deterministic report is the source of truth; LLM analysis is advisory only

## Links

- **GitHub:** [github.com/Aegis-Scan/aegis-scan](https://github.com/Aegis-Scan/aegis-scan)
- **PyPI:** [pypi.org/project/aegis-audit](https://pypi.org/project/aegis-audit/)
- **License:** AGPL-3.0 (commercial license available)
- **Skill Developer Guide:** [docs/SKILL_DEVELOPER_GUIDE.md](https://github.com/Aegis-Scan/aegis-scan/blob/main/docs/SKILL_DEVELOPER_GUIDE.md)
