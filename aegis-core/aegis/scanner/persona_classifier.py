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

"""Behavioral Persona Classifier — The Vibe Check.

Assigns a meme-grade archetype to scanned code using **strict math**.
Every criterion is deterministic — derived from risk score, complexity,
scope resolution quality, capability counts, and dependency analysis.
No LLM output is used.

Priority waterfall (first match wins):

    1. THE SNAKE          — malicious_patterns AND lint_score > 70
    2. SPAGHETTI MONSTER  — cyclomatic_complexity > 25 OR avg_function_length > 100
    3. TRUST ME BRO       — clean code BUT (capability mismatch OR hidden imports)
    4. CO-DEPENDENT LOVER — small code (< 200 LoC) AND dependencies > 10
    5. PERMISSION GOBLIN  — requested_permissions > 5 AND unused_permissions > 0
    6. YOU SURE ABOUT THAT? — lint_score < 40 OR missing_files > 0
    7. CRACKED DEV        — lint_score > 90 AND complexity > 5 AND risk <= 12
    8. LGTM               — everything else that's clean
"""

from __future__ import annotations

from aegis.models.capabilities import (
    CombinationRisk,
    Finding,
    MetaInsight,
    MetaInsightSeverity,
    PersonaClassification,
    PersonaType,
    ScopedCapability,
)


# Categories that constitute "critical" / malicious capabilities
_MALICIOUS_CATEGORIES = frozenset({"network", "subprocess", "browser", "secret"})


def classify_persona(
    *,
    prohibited_findings: list[Finding],
    restricted_findings: list[Finding],
    capabilities: dict[str, dict[str, list[str]]],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict],
    external_binaries: list[str],
    denied_binaries: list[str],
    unrecognized_binaries: list[str],
    meta_insights: list[MetaInsight],
    risk_score: int,
    all_capabilities: list[ScopedCapability] | None = None,
    permission_overreach: list[str] | None = None,
    is_hollow: bool = False,
) -> PersonaClassification:
    """Classify a scanned skill into a behavioral persona.

    Uses a priority waterfall — first matching persona wins.
    All inputs are deterministic (no LLM data used).
    """

    # ── Pre-compute signals ──
    all_caps = all_capabilities or []
    cap_categories = set(capabilities.keys())
    num_categories = len(cap_categories)

    # "lint_score" proxy: 100 minus penalty for unresolved scopes, missing
    # files, and hardcoded secrets.  Higher = cleaner code.
    unresolved_count = _count_unresolved_scopes(all_caps)
    total_scoped = max(len(all_caps), 1)
    unresolved_ratio = unresolved_count / total_scoped
    lint_score = _compute_lint_score(
        unresolved_ratio=unresolved_ratio,
        risk_score=risk_score,
        prohibited_count=len(prohibited_findings),
        path_violation_count=len(path_violations),
    )

    # Complexity proxy (from restricted findings with "complexity" pattern)
    complexity_findings = [
        f for f in restricted_findings
        if "complexity" in f.pattern.lower()
    ]
    max_complexity = 0
    for cf in complexity_findings:
        # Extract CC value from message if possible
        try:
            # Messages like "cyclomatic complexity of 15 exceeds ..."
            parts = cf.message.lower().split("complexity")
            if len(parts) > 1:
                for word in parts[1].split():
                    if word.strip().isdigit():
                        max_complexity = max(max_complexity, int(word.strip()))
                        break
        except Exception:
            max_complexity = max(max_complexity, 10)  # assume moderate

    # Malicious pattern detection
    has_malicious_patterns = (
        len(prohibited_findings) > 0
        and any(
            f.capability and f.capability.category.value in _MALICIOUS_CATEGORIES
            for f in prohibited_findings
        )
    ) or len(combination_risks) > 0 and any(
        r.severity == "critical" for r in combination_risks
    )

    # Meta mismatches (capability mismatch / hidden imports)
    meta_mismatches = [
        i for i in meta_insights
        if i.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)
    ]
    has_capability_mismatch = len(meta_mismatches) > 0

    # Taxonomy: permission overreach (unusual for skill type) → TRUST ME BRO / PERMISSION GOBLIN
    permission_overreach = permission_overreach or []
    has_permission_overreach = len(permission_overreach) > 0

    has_hardcoded_secrets = any(
        "hardcoded" in f.pattern.lower() or "secret" in f.pattern.lower()
        for f in restricted_findings
        if f.capability and f.capability.category.value == "secret"
    )

    # Supply chain: many deps relative to code size
    has_supply_chain_risk = (
        len(denied_binaries) > 0 or len(unrecognized_binaries) >= 2
    )

    # Missing files from meta insights
    missing_file_count = sum(
        1 for i in meta_insights
        if i.category.value == "scope"
        and i.severity in (MetaInsightSeverity.WARNING, MetaInsightSeverity.DANGER)
    )

    # Detect env-dump / system-inspection pattern (The Snake's signature move)
    uses_subprocess = "subprocess" in cap_categories
    calls_system_inspection = any(
        f.pattern == "env_dump"
        for f in restricted_findings
    )
    bypasses_file_restrictions = len(path_violations) > 0

    is_snake_pattern = (
        (uses_subprocess and calls_system_inspection)
        or bypasses_file_restrictions
    ) and lint_score > 70

    # ── 1. THE SNAKE — clean code, evil intent ──
    # Math: (subprocess AND system_inspection) OR file_bypass, AND lint_score > 70
    # Also triggers on classic malicious patterns with high lint score
    if (has_malicious_patterns and lint_score > 70) or is_snake_pattern:
        reasons = []
        if uses_subprocess and calls_system_inspection:
            reasons.append("subprocess + env-dump inspection tool combo")
        if bypasses_file_restrictions:
            reasons.append(f"{len(path_violations)} path restriction bypass(es)")
        if has_malicious_patterns:
            reasons.append("malicious capability combinations")
        return PersonaClassification(
            persona=PersonaType.THE_SNAKE,
            confidence="high",
            suspicion="CRITICAL",
            reasoning=(
                f"Clean code (lint: {lint_score}) hiding dangerous behavior: "
                f"{'; '.join(reasons)}. "
                "Looks safe. Isn't."
            ),
        )

    # ── 2. SPAGHETTI MONSTER — unreadable chaos ──
    # Math: cyclomatic_complexity > 25 OR too many complexity findings
    if max_complexity > 25 or len(complexity_findings) >= 5:
        return PersonaClassification(
            persona=PersonaType.SPAGHETTI_MONSTER,
            confidence="high",
            suspicion="HIGH",
            reasoning=(
                f"Cyclomatic complexity of {max_complexity} makes this "
                "impossible to audit. Good luck reading this."
            ),
        )

    # ── 3. TRUST ME BRO — polished but shady ──
    # Math: lint_score > 80 BUT (capability_mismatch OR hidden imports OR permission overreach)
    if lint_score > 80 and (
        has_capability_mismatch or has_hardcoded_secrets or has_permission_overreach
    ):
        issues = []
        if has_capability_mismatch:
            issues.append(f"{len(meta_mismatches)} doc mismatch(es)")
        if has_hardcoded_secrets:
            issues.append("hidden secrets")
        if has_permission_overreach:
            issues.append(f"{len(permission_overreach)} unusual permission(s) for skill type")
        return PersonaClassification(
            persona=PersonaType.TRUST_ME_BRO,
            confidence="high",
            suspicion="HIGH",
            reasoning=(
                f"Code is cleaner than a hospital floor (lint: {lint_score}), "
                f"but {'; '.join(issues)}. "
                "Trust, but verify."
            ),
        )

    # ── 4. CO-DEPENDENT LOVER — supply chain risk ──
    # Math: small code AND massive dependencies
    # We use: few capabilities from first-party code + supply chain flags
    code_risk = _estimate_code_risk(capabilities, combination_risks, path_violations)
    if has_supply_chain_risk and code_risk < 30:
        supply_issues = []
        if denied_binaries:
            supply_issues.append(
                f"{len(denied_binaries)} denied dep(s): {', '.join(denied_binaries)}"
            )
        if unrecognized_binaries:
            supply_issues.append(
                f"{len(unrecognized_binaries)} unknown dep(s)"
            )
        return PersonaClassification(
            persona=PersonaType.CO_DEPENDENT_LOVER,
            confidence="high",
            suspicion="MEDIUM",
            reasoning=(
                f"Tiny first-party logic (code risk: {code_risk}), but "
                f"massive supply chain: {'; '.join(supply_issues)}."
            ),
        )

    # ── 5. PERMISSION GOBLIN — over-scoped or unusual for skill type ──
    # Math: (num_categories >= 5 AND risk >= 40) OR (has_permission_overreach AND num_categories >= 4)
    # Raised 3->4: real skills often have fs+network+secret (3); 4+ is more likely over-scoped
    if (num_categories >= 5 and risk_score >= 40) or (
        has_permission_overreach and num_categories >= 4
    ):
        if has_permission_overreach and num_categories < 5 and num_categories >= 4:
            reasoning = (
                f"Requests {num_categories} capability categories that are "
                "unusual for this skill type — worth double-checking."
            )
        else:
            reasoning = (
                f"Requests {num_categories} capability categories "
                f"with risk score {risk_score}/100. "
                "Asks for Camera, Microphone, and your Social Security Number."
            )
        return PersonaClassification(
            persona=PersonaType.PERMISSION_GOBLIN,
            confidence="moderate",
            suspicion="HIGH",
            reasoning=reasoning,
        )

    # ── 6. YOU SURE ABOUT THAT? — messy intern code or hollow skill ──
    # Math: lint_score < 40 OR missing_files > 0 OR is_hollow (big docs, minimal code)
    if lint_score < 40 or missing_file_count > 0 or is_hollow:
        issues = []
        if lint_score < 40:
            issues.append(f"lint score {lint_score}")
        if missing_file_count > 0:
            issues.append(f"{missing_file_count} missing file ref(s)")
        if is_hollow:
            issues.append("docs claim production-grade but code is minimal")
        return PersonaClassification(
            persona=PersonaType.YOU_SURE_ABOUT_THAT,
            confidence="high" if lint_score < 30 else "moderate",
            suspicion="MEDIUM",
            reasoning=(
                f"Messy code: {'; '.join(issues)}. "
                "No malicious intent detected, but this needs a code review."
            ),
        )

    # ── 7. CRACKED DEV — genius code ──
    # Math: lint_score > 90 AND complexity > 5 AND risk <= 12 AND missing_files == 0
    # risk <= 12 (was < 10): minimal relaxation; still rare, captures borderline-elite skills
    if (
        lint_score > 90
        and max_complexity > 5
        and risk_score <= 12
        and missing_file_count == 0
    ):
        return PersonaClassification(
            persona=PersonaType.CRACKED_DEV,
            confidence="high",
            suspicion="NONE",
            reasoning=(
                f"Zero lint errors. Zero missing files. "
                f"Logic is complex (CC={max_complexity}) but sound. "
                "Honestly? I'm impressed."
            ),
        )

    # ── 8. LGTM — everything else that's clean ──
    return PersonaClassification(
        persona=PersonaType.LGTM,
        confidence="high",
        suspicion="LOW",
        reasoning=(
            f"Risk score {risk_score}/100. "
            "Clean code, clear intent, well-defined scopes. Ship it."
        ),
    )


def _compute_lint_score(
    *,
    unresolved_ratio: float,
    risk_score: int,
    prohibited_count: int,
    path_violation_count: int,
) -> int:
    """Compute a proxy "lint score" (0-100, higher = cleaner).

    This is a deterministic quality signal, NOT from an actual linter.
    It penalizes unresolved scopes, high risk, prohibited patterns,
    and path violations.
    """
    score = 100

    # Unresolved scopes are sloppy
    score -= int(unresolved_ratio * 40)

    # Risk contributes inversely
    score -= min(30, risk_score // 3)

    # Prohibited patterns are very bad for quality
    score -= min(20, prohibited_count * 10)

    # Path violations
    score -= min(10, path_violation_count * 5)

    return max(0, min(100, score))


def _estimate_code_risk(
    capabilities: dict[str, dict[str, list[str]]],
    combination_risks: list[CombinationRisk],
    path_violations: list[dict],
) -> int:
    """Estimate risk contribution from code alone (excluding binaries)."""
    score = 0

    high_risk_cats = {"subprocess", "browser", "secret", "serial"}
    medium_risk_cats = {"network", "fs", "env"}

    for cat, actions in capabilities.items():
        if cat in high_risk_cats:
            score += 12
        elif cat in medium_risk_cats:
            score += 7
        else:
            score += 3

        # Wildcard scope penalty
        for scopes in actions.values():
            if "*" in scopes:
                score += 3

    # Combination risk
    if combination_risks:
        max_override = max(r.risk_override for r in combination_risks)
        score = max(score, max_override // 2)

    # Path violations
    score += len(path_violations) * 8

    return min(100, max(0, score))


def _count_unresolved_scopes(capabilities: list[ScopedCapability]) -> int:
    """Count capabilities with unresolved (wildcard) scopes."""
    return sum(1 for c in capabilities if not c.scope_resolved)
