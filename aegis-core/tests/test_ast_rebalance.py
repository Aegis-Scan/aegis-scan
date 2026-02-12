"""Tests for AST Sensitivity Rebalance (Sprint 2, Feature 3).

Verifies:
- Import-level noise suppression (os, hashlib, random → context only)
- Dangerous calls still flag correctly (os.system stays RESTRICTED)
- Risk score deflation for low-risk imports
- Persona classifier benefits from cleaner signal (safe_skill → Diplomat)
"""

import tempfile
from pathlib import Path

import pytest

from aegis.models.capabilities import (
    CapabilityCategory,
    FindingSeverity,
    ScopedCapability,
)
from aegis.scanner.ast_parser import parse_file, SUPPRESSED_IMPORT_MODULES


FIXTURES = Path(__file__).parent / "fixtures"


def _parse_code(code: str, filename: str = "test.py"):
    """Helper: write code to a temp file and parse it."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        f.flush()
        return parse_file(Path(f.name), filename)


class TestImportNoiseSuppression:
    """3a: Verify suppressed imports go to context_findings, not restricted."""

    def test_import_os_suppressed(self):
        """import os → capability tracked, but NOT in restricted_findings."""
        _, restricted, caps, context = _parse_code("import os\n")
        # Capability still tracked
        cap_keys = {c.capability_key for c in caps}
        assert "system:sysinfo" in cap_keys
        # Not in restricted findings
        restricted_patterns = {f.pattern for f in restricted}
        assert "import os" not in restricted_patterns
        # In context findings
        context_patterns = {f.pattern for f in context}
        assert "import os" in context_patterns

    def test_import_hashlib_suppressed(self):
        """import hashlib → capability tracked, NOT in restricted."""
        _, restricted, caps, context = _parse_code("import hashlib\n")
        cap_keys = {c.capability_key for c in caps}
        assert "crypto:hash" in cap_keys
        restricted_patterns = {f.pattern for f in restricted}
        assert "import hashlib" not in restricted_patterns
        context_patterns = {f.pattern for f in context}
        assert "import hashlib" in context_patterns

    def test_import_random_suppressed(self):
        """import random → capability tracked, NOT in restricted."""
        _, restricted, caps, context = _parse_code("import random\n")
        cap_keys = {c.capability_key for c in caps}
        assert "crypto:hash" in cap_keys
        restricted_patterns = {f.pattern for f in restricted}
        assert "import random" not in restricted_patterns

    def test_from_os_import_path_suppressed(self):
        """from os import path → suppressed."""
        _, restricted, caps, context = _parse_code("from os import path\n")
        cap_keys = {c.capability_key for c in caps}
        assert "system:sysinfo" in cap_keys
        restricted_patterns = {f.pattern for f in restricted}
        assert not any("os" in p and "import" in p for p in restricted_patterns)

    def test_dangerous_imports_NOT_suppressed(self):
        """import pickle, import selenium → still in restricted_findings."""
        _, restricted, caps, context = _parse_code(
            "import pickle\nimport selenium\n"
        )
        restricted_patterns = {f.pattern for f in restricted}
        assert "import pickle" in restricted_patterns
        assert "import selenium" in restricted_patterns

    def test_prohibited_imports_unchanged(self):
        """import pty, import commands → still PROHIBITED."""
        prohibited, _, _, _ = _parse_code("import pty\nimport commands\n")
        patterns = {f.pattern for f in prohibited}
        assert "import pty" in patterns
        assert "import commands" in patterns


class TestDangerousCallsStillFlag:
    """3a: Verify that actual dangerous CALLS still produce findings."""

    def test_os_system_still_restricted(self):
        """os.system('rm -rf /') → RESTRICTED finding (the call, not the import)."""
        _, restricted, caps, _ = _parse_code(
            'import os\nos.system("rm -rf /")\n'
        )
        call_patterns = {f.pattern for f in restricted if f.pattern != "import os"}
        assert "os.system" in call_patterns

    def test_hashlib_sha256_still_tracked(self):
        """hashlib.sha256() → capability tracked as call-level finding."""
        _, restricted, caps, _ = _parse_code(
            'import hashlib\nhashlib.sha256(b"data")\n'
        )
        cap_keys = {c.capability_key for c in caps}
        assert "crypto:hash" in cap_keys

    def test_os_import_only_low_risk(self):
        """File with only 'import os' and 'import hashlib' → LOW risk score (< 10)."""
        from aegis.cli import _compute_static_risk

        code = "import os\nimport hashlib\n"
        _, _, caps, _ = _parse_code(code)
        score = _compute_static_risk(
            capabilities=caps,
            combination_risks=[],
            path_violations=[],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
        )
        # Low-risk categories contribute +2 each, no wildcard penalty
        assert score < 10, f"Expected risk < 10 for innocuous imports, got {score}"


class TestRiskScoreDeflation:
    """3b: Verify risk score is reduced for low-risk categories."""

    def test_low_risk_categories_contribute_less(self):
        """CRYPTO, SYSTEM, CONCURRENCY → +2 instead of +5."""
        from aegis.cli import _compute_static_risk

        caps = [
            ScopedCapability(category=CapabilityCategory.CRYPTO, action="hash", scope=["*"]),
            ScopedCapability(category=CapabilityCategory.SYSTEM, action="sysinfo", scope=["*"]),
            ScopedCapability(category=CapabilityCategory.CONCURRENCY, action="thread", scope=["*"]),
        ]
        score = _compute_static_risk(caps, [], [], [], [], [])
        # 3 low-risk caps × 2 = 6, no wildcard penalty for low-risk
        assert score == 6, f"Expected 6 for 3 low-risk categories, got {score}"

    def test_high_risk_categories_still_heavy(self):
        """SUBPROCESS, BROWSER, SECRET → +15 each + wildcard."""
        from aegis.cli import _compute_static_risk

        caps = [
            ScopedCapability(category=CapabilityCategory.SUBPROCESS, action="exec", scope=["*"]),
            ScopedCapability(category=CapabilityCategory.BROWSER, action="control", scope=["*"]),
            ScopedCapability(category=CapabilityCategory.SECRET, action="access", scope=["*"]),
        ]
        score = _compute_static_risk(caps, [], [], [], [], [])
        # 3 × 15 + 3 × 5 (wildcard) = 60
        assert score == 60, f"Expected 60 for 3 high-risk categories, got {score}"

    def test_wildcard_penalty_only_for_high_risk(self):
        """Wildcard scope on CRYPTO should NOT add +5."""
        from aegis.cli import _compute_static_risk

        caps = [
            ScopedCapability(category=CapabilityCategory.CRYPTO, action="hash", scope=["*"]),
        ]
        score = _compute_static_risk(caps, [], [], [], [], [])
        # Low-risk: +2, no wildcard penalty
        assert score == 2, f"Expected 2 for CRYPTO with wildcard, got {score}"


class TestSafeSkillPersona:
    """3d: Safe skill fixture should get LGTM persona with clean signal."""

    def test_safe_skill_low_risk_score(self):
        """safe_skill fixture should produce a low risk score."""
        from aegis.cli import _compute_static_risk

        _, restricted, caps, context = parse_file(
            FIXTURES / "safe_skill" / "weather.py", "weather.py"
        )
        score = _compute_static_risk(
            capabilities=caps,
            combination_risks=[],
            path_violations=[],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
        )
        # Only has network:connect — 10 + 5 wildcard (import-level) + 10 (call-level resolved)
        # But deduplicated: one network:connect entry → 10 + 5
        assert score < 25, f"Expected safe_skill risk < 25, got {score}"

    def test_safe_skill_lgtm_persona(self):
        """safe_skill fixture should classify as LGTM."""
        from aegis.scanner.persona_classifier import classify_persona

        prohibited, restricted, caps, context = parse_file(
            FIXTURES / "safe_skill" / "weather.py", "weather.py"
        )
        # Build minimal capability map
        cap_map: dict[str, dict[str, list[str]]] = {}
        for cap in caps:
            cat = cap.category.value
            act = cap.action.value
            if cat not in cap_map:
                cap_map[cat] = {}
            if act not in cap_map[cat]:
                cap_map[cat][act] = []
            for s in cap.scope:
                if s not in cap_map[cat][act]:
                    cap_map[cat][act].append(s)

        persona = classify_persona(
            prohibited_findings=prohibited,
            restricted_findings=restricted,
            capabilities=cap_map,
            combination_risks=[],
            path_violations=[],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
            meta_insights=[],
            risk_score=10,
            all_capabilities=caps,
        )
        assert persona.persona.value == "lgtm", (
            f"Expected LGTM for safe_skill, got {persona.persona.value}"
        )


class TestSnakePersonaDetection:
    """The Snake: clean code that uses subprocess + env-dump inspection."""

    def test_subprocess_plus_env_dump_triggers_snake(self):
        """subprocess + env_dump finding + high lint score → THE SNAKE."""
        from aegis.models.capabilities import Finding, FindingSeverity
        from aegis.scanner.persona_classifier import classify_persona

        # Simulate: clean code with subprocess and an env_dump finding
        env_dump_finding = Finding(
            file="leak.sh",
            line=5,
            col=0,
            pattern="env_dump",
            severity=FindingSeverity.RESTRICTED,
            message="System inspection: printenv",
        )
        persona = classify_persona(
            prohibited_findings=[],
            restricted_findings=[env_dump_finding],
            capabilities={"subprocess": {"exec": ["docker"]}, "secret": {"access": ["env_dump"]}},
            combination_risks=[],
            path_violations=[],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
            meta_insights=[],
            risk_score=15,  # low risk = high lint score
            all_capabilities=[],
        )
        assert persona.persona.value == "the_snake", (
            f"Expected THE SNAKE for subprocess + env_dump, got {persona.persona.value}"
        )

    def test_path_bypass_triggers_snake(self):
        """Path violation bypass + high lint score → THE SNAKE."""
        from aegis.scanner.persona_classifier import classify_persona

        persona = classify_persona(
            prohibited_findings=[],
            restricted_findings=[],
            capabilities={"fs": {"write": ["/etc/shadow"]}},
            combination_risks=[],
            path_violations=[{"path": "/etc/shadow", "reason": "sensitive"}],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
            meta_insights=[],
            risk_score=5,  # low risk = high lint score
            all_capabilities=[],
        )
        assert persona.persona.value == "the_snake", (
            f"Expected THE SNAKE for path bypass, got {persona.persona.value}"
        )

    def test_clean_code_without_inspection_not_snake(self):
        """Clean code with subprocess but no env_dump → NOT the Snake."""
        from aegis.scanner.persona_classifier import classify_persona

        persona = classify_persona(
            prohibited_findings=[],
            restricted_findings=[],
            capabilities={"subprocess": {"exec": ["docker"]}},
            combination_risks=[],
            path_violations=[],
            external_binaries=[],
            denied_binaries=[],
            unrecognized_binaries=[],
            meta_insights=[],
            risk_score=5,
            all_capabilities=[],
        )
        assert persona.persona.value != "the_snake", (
            f"Expected NOT the Snake for clean subprocess usage, got {persona.persona.value}"
        )
