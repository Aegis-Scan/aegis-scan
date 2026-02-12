# Aegis Audit 🦞

**Behavioral security scanner for AI agent skills, like on OpenClaw, and MCP tools.**

> The "SSL certificate" for AI agent skills — scan, certify, and govern before you trust.

Aegis answers the question every agent user should ask: *"What can this skill actually do, and should I trust it?"*

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://github.com/Aegis-Scan/aegis-scan/blob/main/aegis-core/LICENSE)

---

## Why Aegis?

AI agents install and run skills with broad system access. Today, you're trusting them blindly. Aegis gives you:

- **Deterministic static analysis** — AST parsing + Semgrep + 15 specialized scanners. Same code = same report, every time.
- **Scope-resolved capabilities** — Not just "accesses the filesystem" but *exactly which files, URLs, hosts, and ports*.
- **Risk scoring** — 0–100 composite score with CWE/OWASP-mapped findings and severity tiers.
- **Cryptographic proof** — Ed25519-signed lockfile with Merkle tree for tamper detection.
- **Optional LLM analysis** — Bring your own key (Gemini, Claude, OpenAI, Ollama, local).

| Feature | Basic Safety Summary | Aegis Audit |
|---|---|---|
| Detection method | LLM reads README | AST + Semgrep + 15 scanners |
| Deterministic | No | Yes |
| Capabilities | High-level categories | Scope-resolved (files/URLs/ports) |
| Vulnerability detection | None | 700+ patterns, CWE-mapped |
| Secret scanning | None | 30+ token patterns |
| Obfuscation detection | None | Base64-exec, homoglyphs, stego |
| Tamper detection | None | Ed25519-signed Merkle tree |
| Fix suggestions | None | Actionable remediation per finding |

---

## Quick Start

### 1. Install

```bash
pip install aegis-audit
```

### 2. Scan a skill

```bash
# Scan the current directory (deterministic, no API key needed)
aegis scan --no-llm

# Scan a specific path
aegis scan ./some-skill --no-llm
```

> **Tip:** All commands default to `.` (the current directory) when no path is given.
> Most users `cd` into a skill and run `aegis scan` from there.

### 3. (Optional) Add LLM analysis

```bash
# Interactive setup — choose provider, model, paste API key
aegis setup

# Then scan with LLM enabled (it's on by default when configured)
aegis scan
```

`aegis setup` saves your config to `~/.aegis/config.yaml`. You can also set an environment variable instead — env vars always take priority over the config file:

```bash
export GEMINI_API_KEY=your-key        # or OPENAI_API_KEY, ANTHROPIC_API_KEY
aegis scan
```

### 4. Generate a signed lockfile

```bash
aegis lock
```

This runs a full scan and generates `aegis.lock` — a cryptographically signed snapshot of the skill's security state. Commit it alongside the skill so consumers can verify nothing changed.

### 5. Verify a lockfile

```bash
aegis verify
```

Checks that the current code matches the signed `aegis.lock`. If any file was modified, the Merkle root won't match and verification fails.

---

## CLI Reference

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

All commands that take `[path]` default to `.` (current directory). Common flags: `--no-llm` (skip LLM), `--json` (CI output), `-v` (verbose). Run `aegis scan --help` (or `aegis lock --help`, etc.) for full flags.

---

## LLM Setup

Aegis works fully offline with deterministic analysis. LLM analysis is **optional** — it adds an AI second opinion on intent and risk but is never required.

### Option A: Interactive setup (recommended)

```bash
aegis setup
```

This walks you through:
1. **Choose a provider** — Gemini, Claude, OpenAI, or a local server (Ollama, LM Studio, llama.cpp, vLLM)
2. **Pick a model** — curated list per provider, or enter a custom model ID
3. **Paste your API key** — hidden input, tested before saving

Config is saved to `~/.aegis/config.yaml`. Run `aegis setup` again anytime to change it.

### Option B: Environment variables

Set one of these and Aegis picks it up automatically:

| Variable | Provider |
|---|---|
| `GEMINI_API_KEY` | Google Gemini |
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic Claude |

For local servers:

| Variable | Description |
|---|---|
| `OLLAMA_HOST` | Ollama server URL (default: `http://localhost:11434`) |
| `AEGIS_LOCAL_OPENAI_URL` | Any OpenAI-compatible server URL |
| `AEGIS_LLM_PROVIDER` | Force a specific provider: `openai`, `gemini`, `claude`, `ollama`, `local_openai` |

See the [full README on GitHub](https://github.com/Aegis-Scan/aegis-scan/blob/main/README.md) for the complete list of model override variables.

---

We've established personas for code repositories that run with our deterministic checks, no LLM is required. Get to know our code personas:

## Vibe Check Personas

Aegis assigns each scanned skill a persona based on deterministic analysis. The Vibe Check shows one of these:

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

---

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
│   🤔  You Sure About That?                                  │
│   The intern special. Messy code, missing pieces,           │
│   docs that overpromise. No malicious intent, but it       │
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
│   🤔  You Sure About That?                                  │
│   ####----------------  22/100 - LOW                         │
╰─────────────────────────────────────────────────────────────╯
╭─ Scan Complete ─────────────────────────────────────────────╮
│   Report: ./aegis_report.json                                │
│   Run aegis lock to generate a signed lockfile.             │
╰─────────────────────────────────────────────────────────────╯
```

---

## What Gets Scanned

| Scanner | What It Detects |
|---|---|
| **AST Parser** | 750+ Python function/method patterns across 15+ categories |
| **Semgrep Rules** | 80+ regex rules for Python, JavaScript, and secrets |
| **Secret Scanner** | API keys, tokens, private keys, connection strings (30+ patterns) |
| **Shell Analyzer** | Pipe-to-shell, reverse shells, inline exec |
| **JS Analyzer** | XSS, eval, prototype pollution, dynamic imports |
| **Dockerfile Analyzer** | Privilege escalation, secrets in ENV/ARG, unpinned images |
| **Config Analyzer** | Dangerous settings in YAML, JSON, TOML, INI |
| **Social Engineering** | Misleading filenames, Unicode tricks, trust manipulation |
| **Steganography** | Hidden payloads in images, homoglyph attacks |
| **Shadow Module Detector** | Stdlib-shadowing files (`os.py`, `sys.py` in the skill) |
| **Combo Analyzer** | Multi-capability attack chains (exfiltration, C2, ransomware) |
| **Taint Analysis** | Source-to-sink data flows (commands, URLs, SQL, paths) |
| **Complexity Analyzer** | Cyclomatic complexity warnings for hard-to-audit functions |
| **Skill Meta Analyzer** | SKILL.md vs. actual code cross-referencing |
| **Persona Classifier** | Overall trust profile (LGTM, Permission Goblin, etc.) |

---

## Use as an MCP Server

Aegis runs as an MCP server for Cursor, Claude Desktop, and any MCP-compatible client. Three tools are exposed: `scan_skill`, `verify_lockfile`, and `list_capabilities`.

### Add to Cursor

Add this to your `.cursor/mcp.json`:

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

Or generate it automatically:

```bash
aegis mcp-config
```

### Add to Claude Desktop

Add the same block to your Claude Desktop MCP config. Aegis uses stdio transport — no network server needed.

---

## Use as a Cursor Skill (ClawHub)

Aegis is available as a skill on [ClawHub](https://clawhub.com). Install it and your agent will automatically audit skills before enabling them.

See [SKILL.md](https://github.com/Aegis-Scan/aegis-scan/blob/main/SKILL.md) for the full skill specification.

---

## JSON Output for CI

```bash
# Full JSON report to stdout
aegis scan --json --no-llm

# Pipe into jq to extract the risk score
aegis scan --json --no-llm | jq '.deterministic.risk_score_static'

# Fail CI if risk > 50
aegis scan --json --no-llm | jq -e '.deterministic.risk_score_static <= 50'
```

The JSON report contains two payloads:

- **Deterministic** — Merkle tree, capabilities, findings, risk score (reproducible, signed)
- **Ephemeral** — LLM analysis, risk adjustment (non-deterministic, not signed)

---

## Architecture

```
aegis scan ./skill
    │
    ├── coordinator.py       → File discovery (git-aware / directory walk)
    ├── ast_parser.py        → AST analysis + pessimistic scope extraction
    ├── secret_scanner.py    → 30+ secret patterns
    ├── shell_analyzer.py    → Dangerous shell patterns
    ├── js_analyzer.py       → JS/TS vulnerability patterns
    ├── config_analyzer.py   → YAML/JSON/TOML/INI risky settings
    ├── combo_analyzer.py    → Multi-capability attack chains
    ├── taint_analyzer.py    → Source→sink data flow tracking
    ├── binary_detector.py   → External binary classification
    ├── social_eng_scanner   → Social engineering detection
    ├── stego_scanner        → Steganography + homoglyphs
    ├── hasher.py            → Lazy Merkle tree
    ├── signer.py            → Ed25519 signing
    ├── rule_engine.py       → Policy evaluation
    └── reporter/            → JSON + Rich console output
         │
         ▼
    aegis_report.json + aegis.lock
```

---

## For Skill Developers

Building a skill? See the [Skill Developer Best Practices](https://github.com/Aegis-Scan/aegis-scan/blob/main/docs/SKILL_DEVELOPER_GUIDE.md) guide for how to make your skills auditable, trustworthy, and easy to verify.

Run Aegis on your own skill before publishing:

```bash
cd ./my-skill
aegis scan --no-llm -v
```

Fix PROHIBITED findings. Document RESTRICTED ones. Ship with an `aegis.lock`:

```bash
aegis lock
```

---

## License

Aegis is dual-licensed:

- **Open Source:** [AGPL-3.0](https://github.com/Aegis-Scan/aegis-scan/blob/main/aegis-core/LICENSE) — free to use, modify, and distribute. Network service deployments must release source.
- **Commercial:** Proprietary license available for embedding in proprietary products, running without source disclosure, SLAs, and support.

See [LICENSING.md](https://github.com/Aegis-Scan/aegis-scan/blob/main/aegis-core/LICENSING.md) for full details. For enterprise inquiries: [enterprise@aegis.network](mailto:enterprise@aegis.network).

---

## Contributing

Contributions welcome. By contributing, you agree to the [Contributor License Agreement](https://github.com/Aegis-Scan/aegis-scan/blob/main/aegis-core/CLA.md).

```bash
cd aegis-core
pip install -e ".[dev]"
pytest
```

---

**Python 3.11+ required** | **No network access needed for deterministic scans** | **Works offline**
