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
aegis scan [PATH] [--no-llm] [--json] [--verbose] [--quiet] [--no-semgrep] [--semgrep-rules PATH]
```

All commands default to `.` (current directory) when no path is given.

| Flag | Description |
|---|---|
| `--no-llm` | Skip LLM analysis (faster, no API cost) |
| `--json` | Output raw JSON to stdout (for CI pipelines) |
| `-v`, `--verbose` | Show per-file findings and extra detail |
| `-q`, `--quiet` | Suppress all output except errors |
| `--no-semgrep` | Skip bundled Semgrep rules |
| `--semgrep-rules PATH` | Path to a custom Semgrep rules directory |

### `verify_lockfile`
Verify an existing `aegis.lock` against current code. Detects any file modifications,
additions, or deletions since the lockfile was generated.

```
aegis verify [PATH] [--strict] [--json] [--lockfile PATH]
```

| Flag | Description |
|---|---|
| `--strict` | Bit-for-bit hash check — fail if ANY file changed (including whitespace) |
| `--json` | Output verification result as JSON |
| `--lockfile PATH` | Path to `aegis.lock` (default: `<path>/aegis.lock`) |

### `list_capabilities`
Lightweight capability extraction without full vulnerability analysis. Fast way to see
what a skill can do without computing risk scores or hashes.

### Other commands

| Command | Description |
|---|---|
| `aegis lock [PATH]` | Scan + generate signed `aegis.lock` (use `--force` for CRITICAL risk) |
| `aegis badge [PATH]` | Generate a shields.io badge for your README |
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
|---|---|
| `GEMINI_API_KEY` | Google Gemini |
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic Claude |
| `OLLAMA_HOST` | Ollama server URL |
| `AEGIS_LOCAL_OPENAI_URL` | Any OpenAI-compatible server |
| `AEGIS_LLM_PROVIDER` | Force provider: `openai`, `gemini`, `claude`, `ollama`, `local_openai` |

## What Gets Scanned

Aegis analyzes **all** files in a skill directory:

| Scanner | What It Detects |
|---|---|
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

## Example Output

A high-risk skill with browser automation, credential access, and network calls:

```
┌─ Aegis Security Audit ──────────────────────────────────────────────────┐
│ AEGIS SECURITY AUDIT                                                    │
│   Target: ./my-skill                                                    │
│   Files:  1 (1 Python)                                                  │
│   Source: directory                                                      │
│   Mode:   AST-only                                                      │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Vibe Check ────────────────────────────────────────────────────────────┐
│   [*]  LGTM                                                             │
│                                                                          │
│   ###################-  95/100 - HIGH RISK - review carefully            │
│                                                                          │
│   Aegis scored this skill 95/100. The most notable finding:              │
│   3 capability combination(s) where permissions reinforce each other     │
│   in ways that could be misused. Aegis flagged 3 possible hardcoded     │
│   secret(s).                                                             │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Capabilities (3) ──────────────────────────────────────────────────────┐
│   BROWSER: can control                                                   │
│     Scope: * (unresolved)                                                │
│                                                                          │
│   NETWORK: can make outbound connections                                 │
│     Scope: *, https://shop.example.com/api/check                         │
│                                                                          │
│   SECRET: can access stored credentials                                  │
│     Scope: *, shopping                                                   │
└─────────────────────────────────────────────────────────────────────────┘
┌─ What Could Go Wrong ──────────────────────────────────────────────────┐
│   1. Credential theft: the skill can read stored secrets and send data  │
│   over the network.                                                      │
│                                                                          │
│   2. Session hijacking: the skill controls a web browser and can        │
│   interact with your active sessions as if it were you.                  │
└─────────────────────────────────────────────────────────────────────────┘
```

When prohibited patterns like `eval()` or `exec()` are found, Aegis blocks certification entirely:

```
┌─ Prohibited Patterns ──────────────────────────────────────────────────┐
│   [ALERT]  BLOCKED — This skill cannot be certified.                    │
│                                                                          │
│   [ALERT]  main.py line 8 in process_input()  CWE-95                    │
│      | result = eval(user_data)                                          │
│      -> Remove dynamic code execution. Use ast.literal_eval().           │
└─────────────────────────────────────────────────────────────────────────┘
```

A clean, low-risk scan:

```
┌─ Vibe Check ────────────────────────────────────────────────────────────┐
│   ####────────────────  22/100 - LOW - minor observations only           │
│                                                                          │
│   Aegis scored this skill 22/100. The code requests minimal permissions  │
│   and nothing looks unusual.                                             │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Findings ──────────────────────────────────────────────────────────────┐
│   [OK]  Permissions: minimal. No high-risk API usage detected.           │
└─────────────────────────────────────────────────────────────────────────┘
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
