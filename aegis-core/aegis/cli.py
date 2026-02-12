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

"""Aegis CLI — Typer entry point.

Commands:
- aegis scan <path>    — Full audit: Vibe Check card, findings, risk score
- aegis lock <path>    — Scan + generate signed lockfile (--force for CRITICAL)
- aegis verify <path>  — Verify an existing aegis.lock matches current code
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from aegis import __version__
from aegis.crypto.hasher import build_merkle_tree, compute_file_hashes
from aegis.crypto.signer import get_or_create_keypair, sign_lockfile
from aegis.models.capabilities import (
    CapabilityCategory,
    CombinationRisk,
    FindingSeverity,
    ScopedCapability,
)
from aegis.models.lockfile import SIGNED_FIELDS, AegisLock
from aegis.models.report import (
    TaxonomyPayload,
    DeterministicPayload,
    EphemeralPayload,
    MerkleTree,
    RiskScore,
    ScanReport,
    UnresolvedScopeAnalysis,
)
from aegis.policy.rule_engine import check_path_violations
from aegis.reporter.console_out import (
    console,
    print_full_report,
    print_verify_result,
)
from aegis.reporter.json_out import to_canonical_json, write_lockfile, write_report
from aegis.scanner.ast_parser import parse_file
from aegis.scanner.binary_detector import (
    classify_binaries,
    get_all_external_binaries,
    has_unrecognized_binaries,
)
from aegis.scanner.combo_analyzer import (
    analyze_combinations,
    get_max_risk_override,
    has_critical_combination,
)
from aegis.scanner.config_analyzer import parse_config_file
from aegis.scanner.coordinator import (
    discover_files,
    get_config_files,
    get_dockerfiles,
    get_js_files,
    get_python_files,
    get_shell_files,
)
from aegis.scanner.complexity_analyzer import analyze_complexity
from aegis.scanner.fix_suggestions import populate_fix_suggestions
from aegis.scanner.dockerfile_analyzer import parse_dockerfile
from aegis.scanner.js_analyzer import parse_js_file
from aegis.scanner.secret_scanner import scan_python_secrets
from aegis.scanner.shadow_detector import detect_shadow_modules
from aegis.scanner.shell_analyzer import parse_shell_file
from aegis.scanner.remediation_feedback import build_one_pass_feedback
from aegis.scanner.skill_meta_analyzer import analyze_skill_meta, extract_declared_tools
from aegis.scanner.skill_taxonomy import compute_documentation_integrity
from aegis.scanner.social_engineering_scanner import scan_file_social_engineering
from aegis.scanner.steganography_scanner import scan_file_steganography
from aegis.scanner.llm_judge import (
    CLAUDE_DEFAULT_MODEL,
    CONFIG_FILE,
    GEMINI_DEFAULT_MODEL,
    LOCAL_OPENAI_DEFAULT_URL,
    OLLAMA_DEFAULT_MODEL,
    OPENAI_DEFAULT_MODEL,
    create_provider,
    create_provider_from_inputs,
    load_config,
    run_llm_analysis,
    save_config,
)
from aegis.scanner.persona_classifier import classify_persona
from aegis.scanner.semgrep_adapter import (
    deduplicate_findings,
    evaluate_semgrep_rules,
    load_semgrep_rules,
)

app = typer.Typer(
    name="aegis",
    help=(
        "Aegis: Behavioral Liability & Assurance Platform — CLI Scanner. "
        "Run 'aegis <command> --help' for flags (e.g. aegis scan --help for -v, --json, --no-llm)."
    ),
    add_completion=False,
)

logger = logging.getLogger("aegis")


# High-risk categories get full wildcard scope penalty; low-risk do not
_HIGH_RISK_CATEGORIES = frozenset({
    CapabilityCategory.SUBPROCESS,
    CapabilityCategory.BROWSER,
    CapabilityCategory.SECRET,
    CapabilityCategory.NETWORK,
    CapabilityCategory.FS,
})

# Low-risk categories contribute less per capability
_LOW_RISK_CATEGORIES = frozenset({
    CapabilityCategory.CRYPTO,
    CapabilityCategory.SYSTEM,
    CapabilityCategory.CONCURRENCY,
})

_GEMINI_MODELS = (
    "gemini-3-pro-preview",
    "gemini-3-flash-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
)

_CLAUDE_MODELS = (
    "claude-opus-4-6",
    "claude-opus-4-5",
    "claude-sonnet-4-20250514",
    "claude-3-7-sonnet-latest",
    "claude-3-5-haiku-latest",
)

_OPENAI_MODELS = (
    "gpt-5.2",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-4.1",
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-3.5-turbo",
)

_LOCAL_MODELS = (
    "llama3.2",
    "llama3.1",
    "llama3",
    "mistral",
    "codellama",
    "phi3",
    "gemma2",
    "qwen2",
)


def _is_interactive_session(*, output_json: bool, quiet: bool) -> bool:
    """Return True when we can safely prompt the user."""
    return (
        not output_json
        and not quiet
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )


def _prompt_menu(prompt: str, options: list[tuple[str, str]], default_idx: int = 1) -> str:
    """Show a numbered choice menu and return selected value."""
    console.print(f"\n[bold]{prompt}[/bold]")
    for idx, (_, label) in enumerate(options, start=1):
        console.print(f"  {idx}. {label}")

    max_idx = len(options)
    while True:
        selection = typer.prompt("Enter number", default=default_idx, type=int)
        if 1 <= selection <= max_idx:
            return options[selection - 1][0]
        console.print(f"[yellow]Please choose a number between 1 and {max_idx}.[/yellow]")


def _prompt_model(provider: str) -> str:
    """Prompt for a provider-specific model."""
    if provider == "gemini":
        options = [(m, m) for m in _GEMINI_MODELS] + [("__custom__", "Custom model ID...")]
        selected = _prompt_menu("Choose Gemini model", options, default_idx=2)
        if selected == "__custom__":
            return typer.prompt("Enter Gemini model ID").strip()
        return selected

    if provider == "claude":
        options = [(m, m) for m in _CLAUDE_MODELS] + [("__custom__", "Custom model ID...")]
        selected = _prompt_menu("Choose Claude model", options, default_idx=2)
        if selected == "__custom__":
            return typer.prompt("Enter Claude model ID").strip()
        return selected

    if provider == "openai":
        options = [(m, m) for m in _OPENAI_MODELS] + [("__custom__", "Custom model ID...")]
        selected = _prompt_menu("Choose OpenAI model", options, default_idx=2)
        if selected == "__custom__":
            return typer.prompt("Enter OpenAI model ID").strip()
        return selected

    # local (any OpenAI-compatible server: Ollama, LM Studio, llama.cpp, vLLM, etc.)
    discovered = _discover_ollama_models()
    fallback = list(_LOCAL_MODELS)
    unique_models = list(dict.fromkeys(discovered + fallback))
    options = [(m, m) for m in unique_models] + [("__custom__", "Custom model ID...")]
    selected = _prompt_menu("Choose model", options, default_idx=1)
    if selected == "__custom__":
        return typer.prompt("Enter model ID (as shown in your server)").strip()
    return selected


def _discover_ollama_models() -> list[str]:
    """Return local Ollama model names, best-effort."""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0:
        return []

    models: list[str] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("name"):
            continue
        model = stripped.split()[0]
        if model and model not in models:
            models.append(model)
    return models


def _prompt_llm_provider() -> Optional[object]:
    """Prompt for provider/model/key and build provider instance."""
    provider = _prompt_menu(
        "Choose LLM provider",
        [
            ("gemini", "Gemini (Google cloud)"),
            ("claude", "Claude (Anthropic cloud)"),
            ("openai", "OpenAI (cloud)"),
            ("local_openai", "Local"),
        ],
        default_idx=1,
    )

    if provider in {"gemini", "claude", "openai"}:
        model = _prompt_model(provider)
        if not model:
            console.print("[yellow]No model selected. Continuing in deterministic-only mode.[/yellow]")
            return None
        env_map = {
            "gemini": "GEMINI_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
        }
        env_var = env_map[provider]
        env_value = os.environ.get(env_var, "").strip()
        api_key = typer.prompt(
            f"Paste {env_var} (hidden, press Enter to use existing env var)",
            default="",
            show_default=False,
            hide_input=True,
        ).strip()
        api_key = api_key or env_value
        if not api_key:
            console.print(f"[yellow]{env_var} is required for {provider}.[/yellow]")
            return None
        return create_provider_from_inputs(provider, api_key=api_key, model=model)

    # Local: just URL + model (works with Ollama, LM Studio, llama.cpp, vLLM, etc.)
    console.print(
        "[dim]Tip: Run your local server (Ollama, LM Studio, llama.cpp, etc.) and enter its URL.[/dim]"
    )
    base_url = typer.prompt(
        "Local server URL",
        default=os.environ.get("AEGIS_LOCAL_OPENAI_URL", LOCAL_OPENAI_DEFAULT_URL),
    ).strip()
    base_url = base_url or LOCAL_OPENAI_DEFAULT_URL
    # Ensure /v1 for Ollama if user entered bare host
    if base_url and not base_url.endswith("/v1") and not base_url.endswith("/v1/"):
        if "localhost:11434" in base_url or "127.0.0.1:11434" in base_url:
            base_url = base_url.rstrip("/") + "/v1"
    model = _prompt_model(provider)
    if not model:
        console.print("[yellow]No model selected. Continuing in deterministic-only mode.[/yellow]")
        return None
    return create_provider_from_inputs(
        provider, base_url=base_url, model=model
    )


def _compute_static_risk(
    capabilities: list[ScopedCapability],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict],
    external_binaries: list[str],
    denied_binaries: list[str],
    unrecognized_binaries: list[str],
) -> int:
    """Compute the deterministic static risk score (0-100).

    Factors:
    - Number and type of capabilities
    - Unresolved scopes (wildcard) — only for high-risk categories
    - Combination risk overrides
    - Path violations
    - Denied/unrecognized binaries
    """
    score = 0

    # Cap per-category contribution to avoid noise inflation
    # Use a set to deduplicate categories for base scoring
    seen_category_actions: set[tuple[CapabilityCategory, str]] = set()

    for cap in capabilities:
        key = (cap.category, cap.action.value)
        if key in seen_category_actions:
            continue
        seen_category_actions.add(key)

        # High-risk categories
        if cap.category in (
            CapabilityCategory.SUBPROCESS,
            CapabilityCategory.BROWSER,
            CapabilityCategory.SECRET,
        ):
            score += 15
        elif cap.category in (CapabilityCategory.NETWORK, CapabilityCategory.FS):
            score += 10
        elif cap.category == CapabilityCategory.SERIAL:
            score += 12
        elif cap.category in _LOW_RISK_CATEGORIES:
            score += 2  # Low-risk: +2 instead of +5
        else:
            score += 5

        # Wildcard scope penalty — only for high-risk categories
        if "*" in cap.scope and cap.category in _HIGH_RISK_CATEGORIES:
            score += 5

    # Combination risk overrides
    max_override = get_max_risk_override(combination_risks)
    if max_override is not None:
        score = max(score, max_override)

    # Path violations
    score += len(path_violations) * 10

    # Denied binaries
    score += len(denied_binaries) * 10
    score += len(unrecognized_binaries) * 5

    return min(100, max(0, score))


def _build_capability_map(
    capabilities: list[ScopedCapability],
) -> dict[str, dict[str, list[str]]]:
    """Build the structured capability map for the report/lockfile."""
    cap_map: dict[str, dict[str, list[str]]] = {}

    for cap in capabilities:
        cat = cap.category.value
        act = cap.action.value

        if cat not in cap_map:
            cap_map[cat] = {}
        if act not in cap_map[cat]:
            cap_map[cat][act] = []

        for s in cap.scope:
            if s not in cap_map[cat][act]:
                cap_map[cat][act].append(s)

    return cap_map


def _run_scan_pipeline(
    path: str,
    *,
    verbose: bool = False,
    output_json: bool = False,
    quiet: bool = False,
    no_llm: bool = False,
    no_semgrep: bool = False,
    semgrep_rules: Optional[str] = None,
    generate_lockfile: bool = False,
    force_lock: bool = False,
) -> None:
    """Core scan pipeline shared by `scan` and `lock` commands."""
    if quiet:
        logging.basicConfig(level=logging.ERROR)
    elif verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Suppress noisy third-party logs (httpcore, httpx, google_genai, etc.)
    for _name in ("httpcore", "httpx", "google_genai", "openai", "anthropic"):
        _lg = logging.getLogger(_name)
        _lg.setLevel(logging.WARNING)

    target_dir = Path(path).resolve()

    if not target_dir.exists():
        console.print(f"[red]Error: Directory not found: {target_dir}[/red]")
        raise typer.Exit(code=1)

    if not target_dir.is_dir():
        console.print(f"[red]Error: Not a directory: {target_dir}[/red]")
        raise typer.Exit(code=1)

    # ── Step 1: Discover files ──
    all_files, manifest_source = discover_files(target_dir)
    python_files = get_python_files(all_files)
    shell_files = get_shell_files(all_files)
    js_files = get_js_files(all_files)
    config_files = get_config_files(all_files)
    docker_files = get_dockerfiles(all_files)

    # ── Step 2: AST analysis (Python) ──
    all_prohibited = []
    all_restricted = []
    all_capabilities: list[ScopedCapability] = []
    all_context_findings = []  # suppressed import-level findings (for capability map only)
    code_snippets: dict[str, str] = {}

    for rel_path in python_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps, context = parse_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)
        all_context_findings.extend(context)

        # Collect code snippets for LLM (if not --no-llm)
        if not no_llm and (restricted or prohibited):
            try:
                code_snippets[str(rel_path)] = full_path.read_text(encoding="utf-8")
            except Exception:
                pass

    # ── Step 2a: Hardcoded secret detection (Python) ──
    for rel_path in python_files:
        full_path = target_dir / rel_path
        secret_findings, secret_caps = scan_python_secrets(full_path, str(rel_path))
        all_restricted.extend(secret_findings)
        all_capabilities.extend(secret_caps)

    # ── Step 2b: Shell script analysis ──
    for rel_path in shell_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_shell_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # ── Step 2c: JavaScript/TypeScript analysis ──
    for rel_path in js_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_js_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # ── Step 2d: Config file analysis ──
    for rel_path in config_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_config_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # ── Step 2e: Dockerfile analysis ──
    for rel_path in docker_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps = parse_dockerfile(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    # ── Step 2f: Steganography scan (all files) ──
    for rel_path in all_files:
        full_path = target_dir / rel_path
        steg_findings = scan_file_steganography(full_path, str(rel_path))
        for f in steg_findings:
            if f.severity == FindingSeverity.PROHIBITED:
                all_prohibited.append(f)
            else:
                all_restricted.append(f)

    # ── Step 2g: Social engineering pattern scan (all text files) ──
    for rel_path in all_files:
        full_path = target_dir / rel_path
        se_findings = scan_file_social_engineering(full_path, str(rel_path))
        all_restricted.extend(se_findings)

    # ── Step 2h: Stdlib module shadowing detection ──
    shadow_findings = detect_shadow_modules(all_files, target_dir)
    for f in shadow_findings:
        if f.severity == FindingSeverity.PROHIBITED:
            all_prohibited.append(f)
        else:
            all_restricted.append(f)

    # ── Step 2i: Cyclomatic complexity analysis (Python) ──
    for rel_path in python_files:
        full_path = target_dir / rel_path
        complexity_findings = analyze_complexity(full_path, str(rel_path))
        all_restricted.extend(complexity_findings)

    # ── Step 2j: Semgrep rule evaluation ──
    if not no_semgrep:
        # Always load bundled Aegis Standard rules
        bundled_path = Path(__file__).parent / "rules" / "semgrep"
        sg_rules = load_semgrep_rules(bundled_path)

        # Load custom rules directory if specified
        if semgrep_rules:
            custom_path = Path(semgrep_rules).resolve()
            if custom_path.exists() and custom_path.is_dir():
                custom_rules = load_semgrep_rules(custom_path)
                sg_rules.extend(custom_rules)
            else:
                console.print(
                    f"[yellow]Warning: Custom rules directory not found: {custom_path}[/yellow]"
                )
        if sg_rules:
            # Collect Aegis findings for deduplication
            aegis_findings_all = all_prohibited + all_restricted

            semgrep_prohibited_all: list = []
            semgrep_restricted_all: list = []

            # Evaluate against all source and config files
            _all_source_files = (
                list(python_files) + list(js_files) + list(shell_files) + list(config_files)
            )
            for rel_path in _all_source_files:
                full_path = target_dir / rel_path
                try:
                    content = full_path.read_text(encoding="utf-8")
                except Exception:
                    continue

                # Determine language from extension
                suffix = full_path.suffix.lower()
                lang = "generic"
                if suffix == ".py":
                    lang = "python"
                elif suffix in (".js", ".jsx", ".mjs", ".cjs"):
                    lang = "javascript"
                elif suffix in (".ts", ".tsx"):
                    lang = "typescript"
                elif suffix in (".sh", ".bash"):
                    lang = "shell"

                sg_prohibited, sg_restricted, sg_caps = evaluate_semgrep_rules(
                    full_path, str(rel_path), content, lang, sg_rules
                )
                semgrep_prohibited_all.extend(sg_prohibited)
                semgrep_restricted_all.extend(sg_restricted)
                all_capabilities.extend(sg_caps)

            # Deduplicate: prefer Aegis findings over Semgrep
            unique_sg_prohibited = deduplicate_findings(aegis_findings_all, semgrep_prohibited_all)
            unique_sg_restricted = deduplicate_findings(aegis_findings_all, semgrep_restricted_all)

            all_prohibited.extend(unique_sg_prohibited)
            all_restricted.extend(unique_sg_restricted)

    # ── Step 3: Binary detection ──
    external_binaries = get_all_external_binaries(all_capabilities)
    denied_bins, allowed_bins, unrecognized_bins = classify_binaries(external_binaries)

    # ── Step 4: Combination analysis ──
    has_unrec_bins = has_unrecognized_binaries(external_binaries)
    combination_risks = analyze_combinations(
        set(all_capabilities), has_unrecognized_binary=has_unrec_bins
    )

    # ── Step 5: Path violation check ──
    path_violations = check_path_violations(all_capabilities)

    # ── Step 6: Compute hashes + Merkle tree ──
    file_hashes = compute_file_hashes(target_dir, all_files)
    merkle_tree = build_merkle_tree(file_hashes)

    # ── Step 7: Compute static risk score ──
    static_risk = _compute_static_risk(
        all_capabilities,
        combination_risks,
        path_violations,
        external_binaries,
        denied_bins,
        unrecognized_bins,
    )

    # ── Step 8: LLM analysis (if available via env vars or config) ──
    llm_result = {"analysis": None, "risk_adjustment": 0, "unresolved_scope_opinions": []}
    provider_name = None

    if not no_llm:
        provider = create_provider()
        if provider:
            provider_name = provider.__class__.__name__.replace("Provider", "").lower()
            llm_result = run_llm_analysis(
                provider, all_restricted, all_capabilities, code_snippets
            )

    llm_adjustment = llm_result.get("risk_adjustment", 0)
    final_risk = max(0, min(100, static_risk + llm_adjustment))

    # ── Step 10: Build capability map ──
    # Build from all capabilities (including suppressed imports) for internal use
    cap_map = _build_capability_map(all_capabilities)

    # Remove capability categories that ONLY came from suppressed imports
    # (no actual call-level findings). These are noise in the report.
    categories_with_real_findings = {
        f.capability.category.value
        for f in all_restricted
        if f.capability
    }
    suppressed_only_categories = set(cap_map.keys()) - categories_with_real_findings
    for cat in suppressed_only_categories:
        # Only suppress low-risk categories (system, crypto, concurrency)
        if cat in {"system", "crypto", "concurrency"}:
            del cap_map[cat]

    # ── Step 10b: Populate fix suggestions ──
    populate_fix_suggestions(
        all_prohibited + all_restricted, combination_risks
    )
    remediation_feedback = build_one_pass_feedback(
        all_prohibited,
        all_restricted,
        combination_risks,
    )

    # ── Step 10c: SKILL.md / manifest meta-analysis ──
    meta_insights = analyze_skill_meta(
        target_dir=target_dir,
        manifest_files=all_files,
        code_capabilities=cap_map,
        external_binaries=external_binaries,
    )

    # ── Step 10c2: Documentation integrity / taxonomy analysis ──
    skill_md_path = target_dir / "SKILL.md"
    skill_md_text = ""
    if skill_md_path.exists():
        try:
            skill_md_text = skill_md_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

    # Extract declared MCP/OpenClaw tools for tool-bucketing analysis
    declared_tools = extract_declared_tools(target_dir, skill_md_text)

    integrity = compute_documentation_integrity(
        skill_md=skill_md_text,
        code_capabilities=cap_map,
        meta_insights=meta_insights,
        restricted_finding_count=len(all_restricted),
        python_file_count=len(python_files),
        total_file_count=len(all_files),
        declared_tools=declared_tools,
    )

    # Apply documentation integrity risk adjustment
    if integrity.risk_adjustment > 0:
        final_risk = max(0, min(100, final_risk + integrity.risk_adjustment))
        logger.info(
            "Documentation integrity adjustment: +%d (score %d, %s, %s)",
            integrity.risk_adjustment,
            integrity.integrity_score,
            integrity.skill_category,
            "; ".join(integrity.issues) if integrity.issues else "clean",
        )

    # ── Step 10d: Persona classification ──
    # Merge capability + tool overreach for persona (TRUST_ME_BRO / PERMISSION_GOBLIN)
    all_overreach = list(integrity.permission_overreach) + list(integrity.tool_overreach)

    persona = classify_persona(
        prohibited_findings=all_prohibited,
        restricted_findings=all_restricted,
        capabilities=cap_map,
        combination_risks=combination_risks,
        path_violations=path_violations,
        external_binaries=external_binaries,
        denied_binaries=denied_bins,
        unrecognized_binaries=unrecognized_bins,
        meta_insights=meta_insights,
        risk_score=final_risk,
        all_capabilities=all_capabilities,
        permission_overreach=all_overreach,
        is_hollow=integrity.is_hollow,
    )

    # ── Step 11: Build report ──
    report = ScanReport(
        aegis_version=__version__,
        scan_target=str(target_dir),
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        deterministic=DeterministicPayload(
            manifest_source=manifest_source,
            file_count=len(all_files),
            merkle_tree=merkle_tree,
            capabilities=cap_map,
            external_binaries=external_binaries,
            prohibited_findings=all_prohibited,
            restricted_findings=all_restricted,
            combination_risks=combination_risks,
            path_violations=path_violations,
            meta_insights=meta_insights,
            persona=persona,
            remediation_feedback=remediation_feedback,
            risk_score_static=static_risk,
        ),
        ephemeral=EphemeralPayload(
            llm_provider=provider_name,
            llm_analysis=llm_result.get("analysis"),
            llm_risk_adjustment=llm_adjustment,
            risk_score_final=final_risk,
            unresolved_scope_analysis=[
                UnresolvedScopeAnalysis(**s)
                for s in llm_result.get("unresolved_scope_opinions", [])
            ],
            taxonomy=TaxonomyPayload(
                skill_category=integrity.skill_category,
                classification_confidence=integrity.classification_confidence,
                permission_overreach=integrity.permission_overreach,
                tool_overreach=integrity.tool_overreach,
            ),
        ),
    )

    # ── Step 12: Check for hard fail ──
    hard_fail = len(all_prohibited) > 0

    # ── Step 13: Write report ──
    report_path = target_dir / "aegis_report.json"
    if not hard_fail:
        write_report(report, report_path)

    # ── Step 14: Generate lockfile (only when generate_lockfile=True) ──
    lockfile_path = None
    if not hard_fail and generate_lockfile:
        is_critical = final_risk >= 75 or has_critical_combination(combination_risks)

        if is_critical and not force_lock:
            if not quiet and not output_json:
                console.print(
                    "[yellow]CRITICAL risk detected. Use --force to generate lockfile anyway.[/yellow]"
                )
        else:
            # Generate cert ID
            cert_id = f"local-{uuid.uuid4().hex[:12]}"

            # Build lockfile
            lockfile = AegisLock(
                aegis_version=__version__,
                capabilities=cap_map,
                cert_id=cert_id,
                combination_risks=[r.model_dump() for r in combination_risks],
                external_binaries=external_binaries,
                manifest_source=manifest_source,
                merkle_tree=merkle_tree.model_dump(),
                path_violations=path_violations,
                risk_score={
                    "static": static_risk,
                    "llm_adjustment": llm_adjustment,
                    "final": final_risk,
                },
            )

            # Sign with developer key
            private_key, public_key = get_or_create_keypair()
            lockfile = sign_lockfile(lockfile, private_key, public_key)

            # Write lockfile
            lockfile_path_obj = target_dir / "aegis.lock"
            write_lockfile(lockfile.model_dump(), lockfile_path_obj)
            lockfile_path = str(lockfile_path_obj)

            if not quiet and not output_json:
                console.print(
                    "\n[bold green]Lockfile generated.[/bold green] "
                    "Commit this file to pin security state."
                )

    # ── Step 15: Output ──
    if output_json:
        print(to_canonical_json(report.model_dump()), end="")
    elif not quiet:
        print_full_report(
            report,
            verbose=verbose,
            report_path=str(report_path) if not hard_fail else None,
            lockfile_path=lockfile_path,
            python_count=len(python_files),
            shell_count=len(shell_files),
            js_count=len(js_files),
            config_count=len(config_files),
            docker_count=len(docker_files),
            denied_bins=denied_bins,
            unrecognized_bins=unrecognized_bins,
            is_lock_command=generate_lockfile,
            permission_overreach=all_overreach,
        )

    if hard_fail:
        raise typer.Exit(code=1)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan (default: current directory)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-file findings and extra detail"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON to stdout (for CI)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except errors"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis (faster, no API cost)"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip bundled Semgrep rules"),
    semgrep_rules: Optional[str] = typer.Option(None, "--semgrep-rules", help="Path to custom Semgrep rules directory"),
) -> None:
    """Scan a skill directory and print the Vibe Check.

    Runs deterministic analysis (AST + Semgrep). If an LLM is configured
    (aegis setup or env vars), LLM analysis runs automatically. Use
    --no-llm to skip. Add -v for more detail.
    """
    _run_scan_pipeline(
        path,
        verbose=verbose,
        output_json=output_json,
        quiet=quiet,
        no_llm=no_llm,
        no_semgrep=no_semgrep,
        semgrep_rules=semgrep_rules,
    )


@app.command()
def lock(
    path: str = typer.Argument(".", help="Path to scan and lock (default: current directory)"),
    force: bool = typer.Option(False, "--force", help="Generate lockfile even for CRITICAL risk"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-file findings and extra detail"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON to stdout (for CI)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except errors"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip bundled Semgrep rules"),
    semgrep_rules: Optional[str] = typer.Option(None, "--semgrep-rules", help="Path to custom Semgrep rules directory"),
) -> None:
    """Scan a skill directory and generate a signed lockfile.

    Runs a full scan first. If risk is LOW or MEDIUM, generates aegis.lock.
    Use --force to generate even at CRITICAL risk. Add -v for more detail.
    """
    _run_scan_pipeline(
        path,
        verbose=verbose,
        output_json=output_json,
        quiet=quiet,
        no_llm=no_llm,
        no_semgrep=no_semgrep,
        semgrep_rules=semgrep_rules,
        generate_lockfile=True,
        force_lock=force,
    )


@app.command()
def verify(
    path: str = typer.Argument(".", help="Path to verify (default: current directory)"),
    lockfile: Optional[str] = typer.Option(None, "--lockfile", help="Path to aegis.lock (default: <path>/aegis.lock)"),
    strict: bool = typer.Option(
        False, "--strict",
        help="Bit-for-bit hash check — fail if ANY file changed (comments, whitespace)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output verification result as JSON"),
) -> None:
    """Verify an existing aegis.lock matches current code.

    Verifies the Merkle root and developer signature. Use --strict for
    bit-for-bit file hash checks (comments/whitespace changes will fail).
    """
    from aegis.verify.standalone import verify as standalone_verify

    target_dir = Path(path).resolve()
    lockfile_path = Path(lockfile).resolve() if lockfile else None

    passed, messages = standalone_verify(target_dir, lockfile_path, strict)

    if output_json:
        result = {
            "passed": passed,
            "messages": messages,
        }
        print(json.dumps(result, indent=2))
    else:
        details = "\n".join(messages)
        print_verify_result(passed, details)

    if not passed:
        raise typer.Exit(code=1)


@app.command()
def setup() -> None:
    """Configure Aegis LLM provider and save to ~/.aegis/config.yaml.

    Walks through provider selection, model choice, and API key entry.
    The config is used as a fallback when environment variables are not set.
    """
    console.print()
    console.print("[bold cyan]Aegis Setup[/bold cyan]")
    console.print("[dim]─────────────────────────────────────[/dim]")
    console.print()
    console.print("Aegis runs a deterministic code scan by default (no API key needed).")
    console.print("You can optionally add an LLM for deeper intent analysis.")
    console.print()

    # Show existing config if present
    existing = load_config()
    existing_llm = existing.get("llm", {})
    if isinstance(existing_llm, dict) and existing_llm.get("provider"):
        console.print(f"[dim]Current config: provider=[/dim][green]{existing_llm['provider']}[/green]"
                       f"[dim], model=[/dim][green]{existing_llm.get('model', 'default')}[/green]"
                       f"[dim] ({CONFIG_FILE})[/dim]")
        console.print()

    configure = typer.confirm("Would you like to configure an LLM provider?", default=True)
    if not configure:
        console.print("[dim]Skipping LLM configuration. Run 'aegis scan' for deterministic-only analysis.[/dim]")
        return

    console.print()
    provider = _prompt_llm_provider()

    if provider is None:
        console.print("[yellow]No provider configured. Aegis will run in deterministic-only mode.[/yellow]")
        return

    # Test the connection
    console.print()
    console.print("[dim]Testing connection...[/dim]", end=" ")
    try:
        test_result = provider.analyze_sync("Respond with valid JSON: {\"status\": \"ok\"}")
        if test_result and not isinstance(test_result, dict):
            test_result = {"status": "unknown"}
        console.print("[bold green]OK[/bold green]")
    except Exception as e:
        console.print(f"[bold red]FAILED[/bold red]")
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Config not saved. Check your API key and try again.[/yellow]")
        return

    # Build the config to save
    config_data: dict = {"llm": {}}
    # Extract provider info from the provider object
    if hasattr(provider, "api_key"):
        # Cloud provider (Gemini, Claude, OpenAI)
        provider_name = ""
        if hasattr(provider, "model_name"):
            model_name = provider.model_name
        elif hasattr(provider, "model"):
            model_name = provider.model
        else:
            model_name = ""

        from aegis.scanner.llm_judge import GeminiProvider, ClaudeProvider, OpenAIProvider
        if isinstance(provider, GeminiProvider):
            provider_name = "gemini"
        elif isinstance(provider, ClaudeProvider):
            provider_name = "claude"
        elif isinstance(provider, OpenAIProvider):
            provider_name = "openai"

        config_data["llm"] = {
            "provider": provider_name,
            "model": model_name,
            "api_key": provider.api_key,
        }
    elif hasattr(provider, "base_url"):
        # Local OpenAI-compatible
        config_data["llm"] = {
            "provider": "local_openai",
            "model": provider.model_name,
            "base_url": provider.base_url,
        }
    elif hasattr(provider, "host"):
        # Ollama
        config_data["llm"] = {
            "provider": "ollama",
            "model": provider.model,
            "host": provider.host,
        }

    saved_path = save_config(config_data)
    console.print()
    console.print(f"[bold green]Config saved to {saved_path}[/bold green]")
    provider_name = config_data["llm"].get("provider", "")
    env_var_hint = {
        "gemini": "GEMINI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
    }.get(provider_name, "")
    if env_var_hint:
        console.print(f"[dim]You can also set {env_var_hint} as an environment variable (takes priority over config).[/dim]")
    console.print()
    console.print("[bold]Run 'aegis scan' to try it out![/bold] Add -v (--verbose) for more detail.")


@app.command()
def badge(
    path: str = typer.Argument(".", help="Path to the skill directory to scan (default: current directory)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write badge markdown to file (default: stdout)"),
    no_llm: bool = typer.Option(True, "--no-llm/--llm", help="Skip LLM analysis (default: skip for speed)"),
) -> None:
    """Generate an 'Aegis Verified' badge for your README.

    Runs a quick deterministic scan and produces a shields.io badge.
    Copy-paste into README.md. Risk tiers: 0-25 LOW (green), 26-50
    MODERATE (yellow), 51-75 HIGH (orange), 76-100 CRITICAL (red).
    """
    import urllib.parse

    target_dir = Path(path).resolve()

    if not target_dir.exists() or not target_dir.is_dir():
        console.print(f"[red]Error: Not a valid directory: {target_dir}[/red]")
        raise typer.Exit(code=1)

    # Run a lightweight scan to get the risk score
    console.print("[dim]Scanning for badge...[/dim]")

    # Import scan internals
    from aegis.scanner.coordinator import (
        discover_files,
        get_config_files,
        get_dockerfiles,
        get_js_files,
        get_python_files,
        get_shell_files,
    )

    all_files, _ = discover_files(target_dir)
    python_files = get_python_files(all_files)
    shell_files = get_shell_files(all_files)
    js_files = get_js_files(all_files)
    config_files = get_config_files(all_files)
    docker_files = get_dockerfiles(all_files)

    all_prohibited = []
    all_restricted = []
    all_capabilities: list[ScopedCapability] = []

    for rel_path in python_files:
        full_path = target_dir / rel_path
        prohibited, restricted, caps, _ = parse_file(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    for rel_path in python_files:
        full_path = target_dir / rel_path
        from aegis.scanner.secret_scanner import scan_python_secrets as _scan_secrets
        secret_findings, secret_caps = _scan_secrets(full_path, str(rel_path))
        all_restricted.extend(secret_findings)
        all_capabilities.extend(secret_caps)

    for rel_path in shell_files:
        full_path = target_dir / rel_path
        from aegis.scanner.shell_analyzer import parse_shell_file as _parse_shell
        prohibited, restricted, caps = _parse_shell(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    for rel_path in js_files:
        full_path = target_dir / rel_path
        from aegis.scanner.js_analyzer import parse_js_file as _parse_js
        prohibited, restricted, caps = _parse_js(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    for rel_path in config_files:
        full_path = target_dir / rel_path
        from aegis.scanner.config_analyzer import parse_config_file as _parse_cfg
        prohibited, restricted, caps = _parse_cfg(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    for rel_path in docker_files:
        full_path = target_dir / rel_path
        from aegis.scanner.dockerfile_analyzer import parse_dockerfile as _parse_docker
        prohibited, restricted, caps = _parse_docker(full_path, str(rel_path))
        all_prohibited.extend(prohibited)
        all_restricted.extend(restricted)
        all_capabilities.extend(caps)

    from aegis.scanner.binary_detector import (
        classify_binaries as _classify,
        get_all_external_binaries as _get_bins,
        has_unrecognized_binaries as _has_unrec,
    )
    from aegis.scanner.combo_analyzer import analyze_combinations as _analyze_combos

    external_binaries = _get_bins(all_capabilities)
    denied_bins, _, unrecognized_bins = _classify(external_binaries)
    has_unrec_bins = _has_unrec(external_binaries)
    combination_risks = _analyze_combos(
        set(all_capabilities), has_unrecognized_binary=has_unrec_bins
    )
    path_violations = check_path_violations(all_capabilities)

    static_risk = _compute_static_risk(
        all_capabilities, combination_risks, path_violations,
        external_binaries, denied_bins, unrecognized_bins,
    )

    # Determine badge tier
    if static_risk <= 25:
        label = "Aegis Verified"
        status = "LOW Risk"
        color = "brightgreen"
    elif static_risk <= 50:
        label = "Aegis Verified"
        status = "MODERATE"
        color = "yellow"
    elif static_risk <= 75:
        label = "Aegis Scanned"
        status = "HIGH Risk"
        color = "orange"
    else:
        label = "Aegis Scanned"
        status = "CRITICAL Risk"
        color = "red"

    # Build shields.io badge URL
    label_enc = urllib.parse.quote(label)
    status_enc = urllib.parse.quote(f"{status} ({static_risk}/100)")
    badge_url = f"https://img.shields.io/badge/{label_enc}-{status_enc}-{color}?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDFMMy41IDguNXYxMGMwIDIuNSA0IDUgOC41IDcuNSA0LjUtMi41IDguNS01IDguNS03LjV2LTEwTDEyIDFaIiBmaWxsPSIjZmZmIi8+PC9zdmc+"
    link_url = "https://github.com/Aegis-Scan/aegis-scan"

    badge_md = f"[![{label}]({badge_url})]({link_url})"

    if output:
        out_path = Path(output).resolve()
        out_path.write_text(badge_md + "\n", encoding="utf-8")
        console.print(f"[green]Badge written to {out_path}[/green]")
    else:
        console.print()
        console.print("[bold]Copy this into your README.md:[/bold]")
        console.print()
        print(badge_md)
        console.print()

    console.print(f"[dim]Risk score: {static_risk}/100 | {len(all_prohibited)} prohibited | {len(all_restricted)} restricted[/dim]")


@app.command()
def version() -> None:
    """Show the Aegis version."""
    console.print(f"Aegis v{__version__}")


@app.command(name="mcp-serve")
def mcp_serve() -> None:
    """Start the Aegis MCP server (stdio transport).

    This starts an MCP-compatible server that exposes Aegis scanning
    tools for use with Cursor, Claude Desktop, and other MCP clients.
    """
    from aegis.mcp_server import run_server
    run_server()


@app.command(name="mcp-config")
def mcp_config() -> None:
    """Print the MCP config block for Cursor/Claude Desktop settings.

    Copy the output JSON into your Cursor settings or Claude Desktop
    config to register the Aegis MCP server.
    """
    config = {
        "mcpServers": {
            "aegis": {
                "command": "aegis",
                "args": ["mcp-serve"],
                "env": {},
            }
        }
    }
    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    app()
