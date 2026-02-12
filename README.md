# Aegis Audit

**Behavioral security scanner for AI agent skills and MCP tools.**

> The "SSL certificate" for AI agent skills — scan, certify, and govern MCP tools before you trust them.

Aegis answers the question every agent user should ask: *"What can this skill actually do, and should I trust it?"*

---

## Why Aegis?

AI agents install and run skills with broad system access. Today, you're trusting them blindly. Aegis gives you:

- **Deterministic static analysis** — AST parsing + Semgrep + 15 specialized scanners. Same code = same report, every time.
- **Scope-resolved capabilities** — Not just "accesses the filesystem" but *exactly which files, URLs, hosts, and ports*.
- **Risk scoring** — 0-100 composite score with CWE/OWASP-mapped findings and severity tiers.
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

### Install from PyPI

```bash
pip install aegis-audit
```

### Scan a skill

```bash
# Full deterministic scan (no API key needed)
aegis scan ./my-skill --no-llm

# With LLM analysis (optional — set up first)
aegis setup
aegis scan ./my-skill
```

### Generate a signed lockfile

```bash
aegis lock ./my-skill
```

### Verify code hasn't been tampered with

```bash
aegis verify ./my-skill
```

### JSON output for CI pipelines

```bash
aegis scan ./my-skill --json --no-llm
```

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

See [`SKILL.md`](./SKILL.md) for the full skill specification.

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

---

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

---

## CLI Reference

| Command | Description |
|---|---|
| `aegis scan <path>` | Full security scan with risk scoring |
| `aegis lock <path>` | Scan + generate signed `aegis.lock` |
| `aegis verify <path>` | Verify lockfile against current code |
| `aegis badge <path>` | Generate shields.io badge markdown |
| `aegis setup` | Interactive LLM configuration wizard |
| `aegis mcp-serve` | Start the MCP server (stdio transport) |
| `aegis mcp-config` | Print MCP config JSON for Cursor/Claude Desktop |

For full flag reference, see [`aegis-core/README.md`](./aegis-core/README.md).

---

## Environment Variables

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google Gemini API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OLLAMA_HOST` | Ollama server URL (default: `http://localhost:11434`) |
| `AEGIS_LLM_PROVIDER` | Force provider: `openai`, `gemini`, `claude`, `ollama`, `local_openai` |

See [`aegis-core/README.md`](./aegis-core/README.md) for the full list of model override variables.

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

Building a skill? See the [Skill Developer Best Practices](./docs/SKILL_DEVELOPER_GUIDE.md) guide for how to make your skills auditable, trustworthy, and easy to verify.

Run Aegis on your own skill before publishing:

```bash
aegis scan ./my-skill --no-llm --verbose
```

Fix PROHIBITED findings. Document RESTRICTED ones. Ship with an `aegis.lock`.

---

## Project Structure

```
aegis-audit/
├── aegis-core/          # Python package (pip install aegis-audit)
│   ├── aegis/           # Source code
│   │   ├── cli.py       # CLI entry point
│   │   ├── mcp_server.py # MCP server
│   │   ├── scanner/     # All 15+ analyzers
│   │   ├── crypto/      # Hasher + signer
│   │   ├── models/      # Pydantic models
│   │   ├── policy/      # Rule engine
│   │   └── reporter/    # Output formatters
│   ├── tests/           # Test suite
│   ├── pyproject.toml   # Package config
│   └── README.md        # Detailed CLI reference
├── docs/                # Governance & operational docs
│   ├── CHANGELOG.md
│   ├── SKILL_DEVELOPER_GUIDE.md
│   ├── INCIDENT_RESPONSE.md
│   ├── BCP_DR.md
│   ├── RISK_REGISTER.md
│   └── VENDOR_RISK.md
├── scripts/             # Batch scanning utilities
├── .github/             # CI + Dependabot
├── SKILL.md             # ClawHub skill specification
├── LICENSE              # AGPL-3.0
└── LICENSING.md         # Dual license details
```

---

## License

Aegis is dual-licensed:

- **Open Source:** [AGPL-3.0](./aegis-core/LICENSE) — free to use, modify, and distribute. Network service deployments must release source.
- **Commercial:** Proprietary license available for embedding in proprietary products, running without source disclosure, SLAs, and support.

See [LICENSING.md](./aegis-core/LICENSING.md) for full details. For enterprise inquiries: [enterprise@aegis.network](mailto:enterprise@aegis.network).

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://github.com/Aegis-Scan/aegis-scan/blob/main/aegis-core/LICENSE)

---

## Contributing

Contributions welcome. By contributing, you agree to the [Contributor License Agreement](./aegis-core/CLA.md).

```bash
# Development setup
cd aegis-core
pip install -e ".[dev]"
pytest
```

---

**Python 3.11+ required** | **No network access needed for deterministic scans** | **Works offline**
