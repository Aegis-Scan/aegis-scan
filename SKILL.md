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
- **Exactly how dangerous** (risk score 0-100, severity tiers, OWASP mapping)
- **What's hiding** (obfuscated code, homoglyph attacks, shadow modules, steganography)
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
| Risk score | None | 0-100 composite (deterministic + optional LLM) |

## Available Tools

### `scan_skill`
Full security audit of a directory. Returns capabilities, findings, risk score, and
machine-readable remediation feedback.

```
aegis scan [PATH] [--no-llm] [--json] [--verbose]
```

### `verify_lockfile`
Verify an existing `aegis.lock` against current code. Detects any file modifications,
additions, or deletions since the lockfile was generated.

```
aegis verify [PATH] [--strict] [--json]
```

### `list_capabilities`
Lightweight capability extraction without full vulnerability analysis. Fast way to see
what a skill can do without computing risk scores or hashes.

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

Optional LLM support (bring your own API key):

```bash
pip install aegis-audit[llm]
```

**Requires Python 3.11+.** No network access needed for deterministic scans.

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

## Example Output

```
Aegis Scan Report — my-skill v1.0.0
Risk Score: 42/100 (MODERATE)

Capabilities Detected:
  network:connect  → ["api.example.com:443", "httpbin.org"]
  fs:read          → ["./data/*.csv", "/tmp/cache"]
  subprocess:exec  → ["git", "npm"]
  secret:access    → ["$API_KEY", "$DATABASE_URL"]

Findings (7 total):
  PROHIBITED  eval() call at main.py:45
  RESTRICTED  requests.get with user-controlled URL at handler.py:23
  RESTRICTED  subprocess.run with shell=True at deploy.py:12
  ...

Lockfile: aegis.lock generated (Ed25519 signed, Merkle root: abc123...)
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
