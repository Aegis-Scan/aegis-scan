# Aegis: Behavioral Liability & Assurance Platform

> The "SSL Certificate" for AI Agent Skills — scan, certify, and govern MCP tools.

Aegis is a distributed governance infrastructure for the AI Agent economy. This package provides the **CLI Scanner** (Phase 1) — an open-source capability scanner for developers to certify their MCP tools.

## What It Does

- **Scans** Python-based MCP skills/tools for dangerous capabilities
- **Detects** prohibited patterns (eval, exec, dynamic imports, ctypes)
- **Extracts** scoped capabilities with pessimistic static analysis
- **Identifies** "Deadly Trifecta" combination risks (e.g., Browser + Secrets + Network)
- **Flags** sensitive filesystem path violations and denied binary invocations
- **Generates** a cryptographically signed `aegis.lock` lockfile
- **Verifies** code integrity against existing lockfiles

## Installation

```bash
# From PyPI
pip install aegis-audit

# From source
pip install -e .

# With LLM support (optional)
pip install aegis-audit[llm]

# With development tools
pip install -e ".[dev]"
```

**Requirements:** Python 3.11+

## Quick Start

### Configure LLM (optional)

```bash
# Interactive setup — saves config to ~/.aegis/config.yaml
aegis setup

# Or just set an env var (takes priority over config)
export GEMINI_API_KEY=your-key
```

### Scan a skill directory (read-only)

```bash
# Full scan (AST + Semgrep, plus LLM if configured)
aegis scan ./my-skill

# Skip LLM analysis (faster, saves money)
aegis scan ./my-skill --no-llm

# Scan with LLM analysis (requires env var or aegis setup)
aegis scan ./my-skill

# JSON output for CI pipelines
aegis scan ./my-skill --json --no-llm

# Verbose output with per-file findings
aegis scan ./my-skill --verbose --no-llm
```

### Generate a signed lockfile

```bash
# Scan + generate aegis.lock
aegis lock ./my-skill

# Force lockfile even for CRITICAL risk
aegis lock ./my-skill --force
```

### Verify a lockfile

```bash
# Verify aegis.lock matches current code
aegis verify ./my-skill

# Bit-for-bit hash verification (comments, whitespace changes will fail)
aegis verify ./my-skill --strict

# Verify with specific lockfile path
aegis verify ./my-skill --lockfile /path/to/aegis.lock

# JSON output
aegis verify ./my-skill --json
```

### Generate a README badge

```bash
# Print badge markdown for your README
aegis badge ./my-skill

# Write badge to a file
aegis badge ./my-skill --output badge.md
```

### Dependency-free verification

The verifier can run with zero dependencies beyond stdlib + `cryptography`:

```bash
python -m aegis.verify.standalone ./my-skill
```

## CLI Reference

### `aegis setup`

Interactive LLM configuration wizard. Saves your provider, model, and API key to `~/.aegis/config.yaml`. Environment variables always take priority over the config file.

### `aegis scan <path>`

| Flag | Description |
|------|-------------|
| `--verbose`, `-v` | Show per-file findings and LLM reasoning |
| `--json` | Output raw JSON to stdout (for CI) |
| `--quiet`, `-q` | Suppress all output except errors |
| `--no-llm` | Skip AI/LLM analysis (faster, saves money) |
| `--no-semgrep` | Skip bundled static analysis rules |

### `aegis lock <path>`

| Flag | Description |
|------|-------------|
| `--force` | Generate lockfile even for CRITICAL risk |
| `--verbose`, `-v` | Show per-file findings |
| `--json` | Output raw JSON to stdout |
| `--quiet`, `-q` | Suppress all output except errors |
| `--no-llm` | Skip AI/LLM analysis |
| `--no-semgrep` | Skip bundled static analysis rules |

### `aegis verify <path>`

| Flag | Description |
|------|-------------|
| `--lockfile <path>` | Path to aegis.lock (default: `<path>/aegis.lock`) |
| `--strict` | Bit-for-bit hash verification — fail if ANY file changed (including comments, whitespace) |
| `--json` | Output verification result as JSON |

### `aegis badge <path>`

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write badge markdown to a file instead of stdout |
| `--llm/--no-llm` | Include LLM analysis (default: skip for speed) |

## Architecture

```
aegis scan ./skill
    │
    ├── coordinator.py      # File discovery (git / directory walk)
    ├── ast_parser.py       # AST analysis + pessimistic scope extraction
    ├── binary_detector.py  # External binary detection
    ├── combo_analyzer.py   # Trifecta combination risks
    ├── llm_judge.py        # Optional LLM analysis (BYOK)
    ├── hasher.py           # Lazy Merkle tree
    ├── signer.py           # Ed25519 signing
    ├── rule_engine.py      # Policy evaluation
    └── reporter/           # JSON + Rich console output
         │
         ▼
    aegis_report.json + aegis.lock
```

### Key Design Decisions

1. **Pessimistic Scope Extraction** — Only string literals and simple concatenations are resolved. Variables, f-strings, function calls → `scope: ["*"]`. Never guesses.

2. **Extensible Signatures** — The `signatures` field in `aegis.lock` has named slots (`developer`, `registry`). Phase 1 populates `developer` only.

3. **Lazy Merkle Tree** — Every file is a leaf with O(log n) proof verification. The proxy can verify individual files without re-hashing the entire codebase.

4. **Dependency-Free Verification** — `aegis verify` core logic uses only stdlib + `cryptography`. Runs in locked-down CI environments.

5. **Split Risk Score** — `static` (deterministic, signed) + `llm_adjustment` (ephemeral) + `final` (combined). Proxy uses `static` only.

## Outputs

### `aegis_report.json`

Dual-payload report with:
- **Deterministic**: Merkle tree, capabilities, findings, risk score (reproducible)
- **Ephemeral**: LLM analysis, risk adjustment (non-deterministic)

### `aegis.lock`

Canonical JSON lockfile containing:
- Scoped capability map
- Merkle tree with all intermediate nodes
- Ed25519 developer signature
- Static risk score (signed)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `AEGIS_OPENAI_MODEL` | Override OpenAI model (default: `gpt-5-mini`) |
| `AEGIS_GEMINI_MODEL` | Override Gemini model (default: `gemini-2.5-flash`) |
| `AEGIS_CLAUDE_MODEL` | Override Claude model (default: `claude-opus-4-6`) |
| `OLLAMA_HOST` | Ollama server URL (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | Ollama model name (default: `llama3`) |
| `AEGIS_LOCAL_OPENAI_URL` | Local server URL (e.g. `http://localhost:11434/v1` for Ollama, `http://localhost:1234/v1` for LM Studio) |
| `AEGIS_LOCAL_OPENAI_MODEL` | Model name for local OpenAI-compatible server |
| `AEGIS_LLM_PROVIDER` | Force provider: `openai`, `gemini`, `claude`, `ollama`, `local_openai` |

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_ast_parser.py

# Run specific test class
pytest tests/test_hasher.py::TestProofVerification
```

## License

Aegis is dual-licensed:

- **Open Source:** [GNU Affero General Public License v3.0 (AGPL-3.0)](./LICENSE) — free to use, modify, and distribute. If you run a modified version as a network service, you must release your source code under AGPL-3.0.
- **Commercial / Enterprise:** A proprietary license is available for organizations that need to use Aegis without AGPL obligations (e.g., embedding in proprietary products, running as an internal service without source disclosure, SLAs, and priority support).

See [LICENSING.md](./LICENSING.md) for full details on the dual-license model.

For enterprise licensing inquiries, contact [enterprise@aegis.network](mailto:enterprise@aegis.network).
