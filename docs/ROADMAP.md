# Aegis Roadmap

High-level plan for future enhancements. Items below are deferred and not scheduled.

---

## Deferred — Later

### Runtime defenses

- **Tree-sitter incremental parsing** — Real-time streamed analysis for LLM outputs; GLR parsing with error recovery.
- **Neuro-symbolic validation** — Auxiliary LLM + deterministic DFG for taint validation; reduce false positives.
- **U4 logic** — Four-valued logic for hallucination cascade mitigation; uncertainty/null absorption.
- **PEP 578 audit hooks** — Low-level runtime audit hooks for process exec, import, file, network; active prevention.
- **Token jitter** — Side-channel timing defense for streaming output.
- **Client-side taint (WASM)** — Browser-side taint tracking and DOM isolation.

### Compliance and governance

- **Compliance mapping** — Explicit control matrices for SOC2, GDPR, PCI-DSS; attestation workflow.
- **Consumer of remediation feedback** — Pipeline or agent that consumes `remediation_feedback` and performs one-pass corrective rewrites.

### Taint and analysis (future)

- **Multi-hop interprocedural taint** — Cross-function and cross-file taint propagation.
- **Additional taint sources** — Environment variables, config files, network responses.
- **Cross-language taint** — JS/TS ↔ Python boundary flows.

---

## Completed (see CHANGELOG.md)

- Path containment, batch hardening, CI, governance docs
- AST sink expansion (YAML SafeLoader, deserialization, XML)
- Import alias resolution
- Schema gating (MCP)
- Lightweight taint rules (commands, URLs, SQL, paths; expanded sinks; interprocedural one-hop)
- One-pass remediation feedback payload
