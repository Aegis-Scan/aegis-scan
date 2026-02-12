# Changelog

All notable changes to the Aegis scanner and governance infrastructure are documented here.

## [0.1.0] — 2026-02-12

*Initial public release.*

### Security & hardening

#### Operational controls

- **Path containment** — Lockfile verification now rejects leaf paths that escape the target directory (`../`, absolute paths). See `aegis-core/aegis/verify/standalone.py`.
- **Batch script hardening** — Removed `shell=True` from batch scan scripts; switched to argument-list subprocess calls and slug validation. See `scripts/batch_scan_clawhub.py`.
- **CI and supply chain** — Added `.github/workflows/aegis-core-ci.yml` (tests, self-scan, pip-audit, SBOM) and `.github/dependabot.yml`.
- **Governance docs** — Added `docs/INCIDENT_RESPONSE.md`, `docs/BCP_DR.md`, `docs/RISK_REGISTER.md`, `docs/VENDOR_RISK.md`.
- **MCP schema gating** — Strict input validation and structured error responses for MCP tools; capability-key and path constraints.

#### AST and sink coverage

- **Unsafe YAML loader** — `yaml.load` / `yaml.load_all` only flagged when Loader is missing or unsafe; `Loader=yaml.SafeLoader` is accepted.
- **Deserialization sinks** — Added `yaml.load_all`, `yaml.unsafe_load_all`, `shelve.DbfilenameShelf`, `xml.etree.cElementTree.parse` / `fromstring`.
- **Import alias resolution** — Aliased imports (`import os as sys_ops`, `from subprocess import run as r`) now resolve to canonical sink names; `getattr` dangerous-module checks use resolved roots.

#### Taint analysis

- **Source→sink taint flows** — Deterministic tracking for commands, URLs, SQL, and filesystem paths. Sources: `input`, `os.getenv`, request-derived patterns, `sys.argv`, `os.environ`.
- **Expanded sinks** — Command, URL, path (open, os.*, shutil.*), and SQL execute/executemany. Both positional and keyword arguments checked.
- **Path sinks** — Added `os.remove`, `os.unlink`, `os.rename`, `os.makedirs`, `shutil.rmtree`, `shutil.move`, etc.
- **Interprocedural taint** — Functions that return tainted data are treated as taint sources in subsequent calls (one-hop, intra-file).

#### Remediation feedback

- **One-pass feedback payload** — `remediation_feedback` added to CLI scan report and MCP `scan_skill` output. Machine-readable tasks (file, line, pattern, severity, suggested_fix, CWE/OWASP) for generator-driven auto-remediation.

### Test additions

- `test_standalone_verify_security.py` — Path-escape rejection in lockfile verification.
- `test_pdf_research_enhancements.py` — YAML SafeLoader, alias resolution, taint flows (command, URL, SQL, path, interprocedural).
- `test_mcp_server.py` — Schema validation and remediation_feedback presence.
