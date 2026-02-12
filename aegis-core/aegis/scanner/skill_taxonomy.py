# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Skill taxonomy and documentation-integrity analysis.

Skills on ClawHub fall into recognizable categories based on their
SKILL.md description and claimed tech stack.  Each category has an
*expected capability profile* — the set of permissions that would be
normal for a well-built skill of that type.

This module:
  1. Classifies a skill into a taxonomy category from its documentation.
  2. Computes a *documentation integrity score* that measures the gap
     between what the docs claim and what the code provides.
  3. Flags "hollow skills" — big docs with empty/stub implementations.
  4. Evaluates *tool overreach* — declared MCP/OpenClaw tools anomalous
     for the skill type (see tool_bucketing.py).

The integrity score feeds into the risk scorer as a penalty, so a skill
that claims to integrate with AWS/GCP/Azure but has no network code gets
a higher risk score even though its code is harmless.  The reasoning:
hollow docs are either (a) copy-paste spam, or (b) a stage-1 placeholder
that will be filled with real (unchecked) code later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Taxonomy categories ──────────────────────────────────────────────

@dataclass(frozen=True)
class SkillProfile:
    """Expected capability profile for a skill category.

    expected_capabilities: Normal for this skill type — no flag.
    suspicious_capabilities: Unusual for this type — worth double-checking (tone: curious, not alarm).
    sometimes_expected: Borderline — treated as expected for now; could move to unusual with data.
    plausible_exceptions: For messaging — why an unusual cap might be legitimate (cap -> one-line reason).
    """

    name: str
    description: str
    expected_capabilities: frozenset[str]
    suspicious_capabilities: frozenset[str]
    keywords: frozenset[str]
    sometimes_expected: frozenset[str] = frozenset()
    plausible_exceptions: tuple[tuple[str, str], ...] = ()  # (cap, reason) pairs


SKILL_TAXONOMY: dict[str, SkillProfile] = {
    "data-science": SkillProfile(
        name="Data Science / ML",
        description="Statistical modeling, ML training, data analysis",
        expected_capabilities=frozenset({"fs", "subprocess", "system"}),
        suspicious_capabilities=frozenset({"browser", "secret", "serial"}),
        sometimes_expected=frozenset({"env", "concurrency", "crypto", "network"}),
        keywords=frozenset({
            "data science", "machine learning", "statistical", "model",
            "experiment", "feature engineering", "pandas", "numpy",
            "scikit-learn", "pytorch", "tensorflow", "ml", "analytics",
            "prediction", "regression", "classification", "training",
            "huggingface", "wandb", "mlflow", "dataset", "inference",
            "embedding", "transformer", "fine-tun", "h2o", "xgboost", "lightgbm",
        }),
        plausible_exceptions=(
            ("secret", "API keys for Model API, Weights & Biases"),
            ("browser", "Rare — scraping a data source"),
            ("serial", "pickle for model load/save — deserialize from network = RCE risk"),
        ),
    ),
    "browser-automation": SkillProfile(
        name="Browser Automation",
        description="Web scraping, browser control, UI testing",
        expected_capabilities=frozenset({"browser", "network", "fs"}),
        suspicious_capabilities=frozenset({"secret", "subprocess", "serial"}),
        sometimes_expected=frozenset({"env"}),
        keywords=frozenset({
            "browser", "scrape", "scraping", "selenium", "playwright",
            "puppeteer", "web automation", "headless", "crawl",
            "beautifulsoup", "scrapy", "lxml", "screenshot", "pyppeteer",
            "mechanize", "splinter",
        }),
        plausible_exceptions=(
            ("secret", "Login credentials for authenticated scrape"),
            ("subprocess", "Launching browser binary, PDF export"),
            ("serial", "Saving scraped data — deserialize from network = RCE risk"),
        ),
    ),
    "api-integration": SkillProfile(
        name="API Integration",
        description="External API calls, webhooks, data fetching",
        expected_capabilities=frozenset({"network", "env", "secret"}),
        suspicious_capabilities=frozenset({"browser", "subprocess", "fs"}),
        sometimes_expected=frozenset({"crypto"}),
        keywords=frozenset({
            "api", "rest", "graphql", "webhook", "integration",
            "fetch", "endpoint", "oauth", "authentication",
            "openapi", "swagger", "postman", "insomnia",
            "retry", "rate limit",
        }),
        plausible_exceptions=(
            ("browser", "OAuth flow in browser for token"),
            ("subprocess", "Calling curl, gcloud CLI"),
            ("fs", "Caching responses, writing logs"),
        ),
    ),
    "devtools": SkillProfile(
        name="Developer Tools",
        description="Code generation, git, deployment, CI/CD",
        expected_capabilities=frozenset({"fs", "subprocess", "network", "env"}),
        suspicious_capabilities=frozenset({"browser", "secret"}),
        sometimes_expected=frozenset({"system", "serial"}),
        keywords=frozenset({
            "git", "github", "deploy", "ci/cd", "code", "debug",
            "lint", "format", "build", "compile", "vercel", "docker",
            "eslint", "prettier", "black", "ruff", "mypy", "pytest",
            "jest", "dockerfile", "kubernetes", "terraform",
        }),
        plausible_exceptions=(
            ("browser", "E2E tests in CI"),
            ("secret", "Deploy keys, CI secrets"),
        ),
    ),
    "document-processing": SkillProfile(
        name="Document Processing",
        description="PDF, OCR, file conversion, document analysis",
        expected_capabilities=frozenset({"fs"}),
        suspicious_capabilities=frozenset({"browser", "subprocess", "secret"}),
        sometimes_expected=frozenset({"serial", "network"}),
        keywords=frozenset({
            "pdf", "document", "ocr", "word", "excel", "csv",
            "parse", "extract", "convert", "file",
            "pypdf", "pdfplumber", "pdf2image", "pandoc", "tesseract",
            "docx", "xlsx", "tabula",
        }),
        plausible_exceptions=(
            ("subprocess", "pdf2image, pandoc, ImageMagick"),
            ("secret", "API key for cloud OCR"),
        ),
    ),
    "system-ops": SkillProfile(
        name="System Operations",
        description="Monitoring, cron, process management",
        expected_capabilities=frozenset({"system", "subprocess", "fs", "env"}),
        suspicious_capabilities=frozenset({"browser", "secret"}),
        sometimes_expected=frozenset({"network", "concurrency"}),
        keywords=frozenset({
            "monitor", "system", "process", "cron", "daemon",
            "service", "health check", "uptime",
            "supervisor", "systemd", "pm2", "health", "metric",
            "prometheus", "grafana",
        }),
        plausible_exceptions=(
            ("secret", "Vault for secrets injection"),
        ),
    ),
    "communication": SkillProfile(
        name="Communication",
        description="Email, messaging, notifications",
        expected_capabilities=frozenset({"network", "env", "secret"}),
        suspicious_capabilities=frozenset({"fs", "subprocess", "browser"}),
        sometimes_expected=frozenset({"serial"}),
        keywords=frozenset({
            "email", "gmail", "mail", "message", "slack", "discord",
            "notification", "sms", "chat", "telegram",
            "twilio", "sendgrid", "mailgun", "firebase", "fcm",
            "push notification",
        }),
        plausible_exceptions=(
            ("fs", "Attachment handling, draft storage"),
            ("subprocess", "Sending via sendmail CLI"),
        ),
    ),
    "crypto-web3": SkillProfile(
        name="Crypto / Web3",
        description="Blockchain, wallets, smart contracts",
        expected_capabilities=frozenset({"network", "crypto", "env", "secret"}),
        suspicious_capabilities=frozenset({"browser", "subprocess"}),
        keywords=frozenset({
            "blockchain", "crypto", "wallet", "token", "smart contract",
            "web3", "ethereum", "solana", "nft", "defi",
            "hardhat", "foundry", "web3.py", "ethers", "mnemonic", "keystore",
        }),
        plausible_exceptions=(
            ("browser", "Wallet connect, dApp frontend"),
            ("subprocess", "Local node, hardhat"),
        ),
    ),
    "security": SkillProfile(
        name="Security",
        description="Security scanning, auditing, vulnerability detection",
        expected_capabilities=frozenset({"fs", "subprocess", "network", "crypto"}),
        suspicious_capabilities=frozenset({"browser"}),
        sometimes_expected=frozenset({"serial"}),
        keywords=frozenset({
            "security", "audit", "scan", "vulnerability", "pentest",
            "password", "encrypt", "firewall",
            "snyk", "trivy", "bandit", "safety", "pip-audit", "npm audit",
        }),
        plausible_exceptions=(
            ("browser", "Web vulnerability scanning"),
        ),
    ),
    "finance": SkillProfile(
        name="Finance",
        description="Financial data, trading, accounting",
        expected_capabilities=frozenset({"network", "fs"}),
        suspicious_capabilities=frozenset({"subprocess", "browser", "secret"}),
        sometimes_expected=frozenset({"env", "serial"}),
        keywords=frozenset({
            "finance", "stock", "trading", "bank", "payment",
            "invoice", "accounting", "cashflow", "portfolio",
            "alpaca", "plaid", "stripe", "quickbooks", "yahoo", "bloomberg",
        }),
        plausible_exceptions=(
            ("subprocess", "Running a charting library"),
            ("browser", "Scraping financial sites"),
            ("secret", "Broker API keys, trading credentials"),
        ),
    ),
    # ── New categories ──
    "database": SkillProfile(
        name="Database",
        description="SQL, NoSQL, ORMs, database operations",
        expected_capabilities=frozenset({"fs", "network", "secret", "env"}),
        suspicious_capabilities=frozenset({"subprocess"}),
        sometimes_expected=frozenset({"serial"}),
        keywords=frozenset({
            "sql", "postgres", "mysql", "sqlite", "mongodb", "redis",
            "prisma", "sqlalchemy", "django orm",
        }),
        plausible_exceptions=(
            ("subprocess", "pg_dump, mysqldump"),
        ),
    ),
    "ai-agents": SkillProfile(
        name="AI Agents / Orchestration",
        description="LLM agents, tool calls, orchestration",
        expected_capabilities=frozenset(
            {"network", "subprocess", "fs", "env", "secret"}
        ),
        suspicious_capabilities=frozenset({"browser", "serial"}),
        keywords=frozenset({
            "agent", "orchestrat", "orchestration", "tool call", "openai", "anthropic",
            "langchain", "llamaindex", "autogen",
        }),
        plausible_exceptions=(
            ("browser", "Web tool"),
            ("serial", "Tool output parsing — deserialize from network = RCE risk"),
        ),
    ),
    "research": SkillProfile(
        name="Research / Education",
        description="Academic research, tutorials, Jupyter notebooks",
        expected_capabilities=frozenset({"fs", "network", "subprocess"}),
        suspicious_capabilities=frozenset({"browser", "secret"}),
        sometimes_expected=frozenset({"subprocess", "env"}),
        keywords=frozenset({
            "research", "paper", "arxiv", "citation", "jupyter",
            "notebook", "tutorial", "course",
        }),
        plausible_exceptions=(
            ("browser", "Scraping research sites"),
            ("secret", "API keys for paid APIs"),
        ),
    ),
    "infrastructure": SkillProfile(
        name="Infrastructure / DevOps",
        description="Terraform, Kubernetes, cloud provisioning",
        expected_capabilities=frozenset(
            {"subprocess", "network", "fs", "secret", "env"}
        ),
        suspicious_capabilities=frozenset({"browser"}),
        sometimes_expected=frozenset({"system"}),
        keywords=frozenset({
            "terraform", "ansible", "pulumi", "kubernetes", "k8s",
            "cloud", "aws", "gcp", "azure", "vpc", "load balancer",
        }),
    ),
}

# All high-risk capability categories (for general/unclassified fallback)
_HIGH_RISK_CAPS = frozenset({
    "browser", "secret", "subprocess", "network", "fs", "serial", "crypto",
})

# Fallback for skills that don't match any category.
# When unclassified, we assume nothing — any high-risk cap is "worth double-checking".
DEFAULT_PROFILE = SkillProfile(
    name="General Purpose",
    description="Unclassified skill",
    expected_capabilities=frozenset(),
    suspicious_capabilities=_HIGH_RISK_CAPS,
    keywords=frozenset(),
)


def classify_skill_type(skill_md: str) -> tuple[str, SkillProfile, str]:
    """Classify a skill into a taxonomy category from its SKILL.md content.

    Returns (category_key, profile, confidence).  Uses keyword matching with a
    simple scoring system — the category with the most keyword hits wins.

    confidence: "high" (clear winner), "low" (tie or near-threshold), "none" (general)
    """
    if not skill_md:
        return "general", DEFAULT_PROFILE, "none"

    text_lower = skill_md.lower()
    best_key = "general"
    best_score = 0
    best_profile = DEFAULT_PROFILE
    scores: list[tuple[str, int]] = []

    for key, profile in SKILL_TAXONOMY.items():
        score = 0
        for kw in profile.keywords:
            hits = min(3, len(re.findall(re.escape(kw), text_lower)))
            score += hits
        if score > 0:
            scores.append((key, score))
        if score > best_score:
            best_score = score
            best_key = key
            best_profile = profile

    if best_score < 3:
        return "general", DEFAULT_PROFILE, "none"

    # Tie detection: multiple categories with same top score
    top_scores = [s for s in scores if s[1] == best_score]
    if len(top_scores) > 1:
        return best_key, best_profile, "low"  # Tie — pick first, but flag low confidence

    # Near-threshold (3–4 hits) = low confidence
    if best_score <= 4:
        return best_key, best_profile, "low"

    return best_key, best_profile, "high"


def compute_permission_overreach(
    *,
    skill_category: str,
    skill_profile: SkillProfile,
    code_capabilities: dict[str, dict[str, list[str]]],
) -> list[str]:
    """Compute permission overreach — capabilities unusual for this skill type.

    Returns list of one-line messages. Tone: curious, worth double-checking, never alarm.
    """
    if not code_capabilities:
        return []

    code_cats = set(code_capabilities.keys())
    unusual = code_cats & skill_profile.suspicious_capabilities
    if not unusual:
        return []

    # Build lookup for plausible exceptions
    plausible = dict(skill_profile.plausible_exceptions)

    category_display = skill_profile.name
    messages = []
    for cap in sorted(unusual):
        reason = plausible.get(cap, "")
        if reason:
            msg = (
                f"This {category_display} skill requests {cap}. "
                f"Unusual for this type — worth double-checking. Plausible: {reason}"
            )
        else:
            msg = (
                f"This {category_display} skill requests {cap}. "
                "Unusual for this type — worth double-checking."
            )
        messages.append(msg)
    return messages


@dataclass
class IntegrityReport:
    """Result of documentation-integrity analysis."""
    # 0-100: how much the docs match the code (100 = perfect match)
    integrity_score: int = 100
    # Category from taxonomy
    skill_category: str = "general"
    skill_profile: SkillProfile = field(default_factory=lambda: DEFAULT_PROFILE)
    # Classification confidence: "high", "low", "none"
    classification_confidence: str = "none"
    # Capabilities unusual for this skill type — worth double-checking (tone: curious)
    permission_overreach: list[str] = field(default_factory=list)
    # Tools unusual for this skill type (MCP/OpenClaw tool bucketing)
    tool_overreach: list[str] = field(default_factory=list)
    # Specific issues found
    issues: list[str] = field(default_factory=list)
    # Is this a "hollow skill" — big docs, no real code?
    is_hollow: bool = False
    # Risk adjustment from integrity analysis (-50 to +50)
    risk_adjustment: int = 0


def compute_documentation_integrity(
    *,
    skill_md: str,
    code_capabilities: dict[str, dict[str, list[str]]],
    meta_insights: list,  # MetaInsight objects
    restricted_finding_count: int,
    python_file_count: int,
    total_file_count: int,
    declared_tools: list[str] | None = None,
) -> IntegrityReport:
    """Compute a documentation-integrity score.

    This measures the gap between claims and reality.  A skill that claims
    AWS/GCP/Docker but has no network or subprocess code is either spam
    or a ticking time bomb (code will be added later without review).

    The integrity score PENALIZES the risk score — if integrity is low,
    risk goes UP even if the code itself is benign.
    """
    report = IntegrityReport()
    report.skill_category, report.skill_profile, report.classification_confidence = (
        classify_skill_type(skill_md)
    )
    report.permission_overreach = compute_permission_overreach(
        skill_category=report.skill_category,
        skill_profile=report.skill_profile,
        code_capabilities=code_capabilities,
    )

    # Tool bucketing — evaluate declared MCP/OpenClaw tools against taxonomy
    if declared_tools:
        from aegis.scanner.tool_bucketing import compute_tool_overreach
        report.tool_overreach = compute_tool_overreach(
            declared_tools=declared_tools,
            skill_category=report.skill_category,
        )

    if not skill_md:
        return report

    from aegis.models.capabilities import MetaInsightSeverity

    # ── Factor 1: Meta-insight severity ──
    danger_count = sum(
        1 for i in meta_insights if i.severity == MetaInsightSeverity.DANGER
    )
    warning_count = sum(
        1 for i in meta_insights if i.severity == MetaInsightSeverity.WARNING
    )

    if danger_count:
        report.integrity_score -= danger_count * 20
        report.issues.append(
            f"{danger_count} major documentation inconsistenc{'y' if danger_count == 1 else 'ies'}"
        )
    if warning_count:
        report.integrity_score -= warning_count * 10
        report.issues.append(
            f"{warning_count} documentation warning(s)"
        )

    # ── Factor 2: Hollowness detection ──
    # A skill with many Python files but almost no findings is suspicious
    # if the documentation claims substantial capabilities.
    text_lower = skill_md.lower()
    claims_substantial = any(
        kw in text_lower
        for kw in ("production", "enterprise", "scalable", "distributed",
                    "real-time", "high availability", "monitoring")
    )

    if (
        python_file_count >= 2
        and restricted_finding_count == 0
        and claims_substantial
        and len(code_capabilities) <= 1
    ):
        report.is_hollow = True
        report.integrity_score -= 25
        report.issues.append(
            "Documentation claims production-grade capabilities but the code "
            "contains minimal actual implementation"
        )

    # ── Factor 3: Doc length vs code substance ──
    doc_lines = len(skill_md.strip().splitlines())
    if doc_lines > 100 and len(code_capabilities) == 0 and python_file_count > 0:
        report.integrity_score -= 15
        report.issues.append(
            f"Extensive documentation ({doc_lines} lines) but zero code capabilities detected"
        )

    # Clamp
    report.integrity_score = max(0, min(100, report.integrity_score))

    # ── Compute risk adjustment ──
    # Low integrity = higher risk.  This is the key insight:
    # A hollow skill isn't dangerous TODAY but it's either spam or
    # a placeholder that will be filled with unreviewed code later.
    if report.integrity_score < 30:
        report.risk_adjustment = 20
    elif report.integrity_score < 50:
        report.risk_adjustment = 12
    elif report.integrity_score < 70:
        report.risk_adjustment = 5
    else:
        report.risk_adjustment = 0

    return report
