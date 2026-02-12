"""Tests for Semgrep Rule Ingestion (Sprint 2, Feature 1).

Covers:
- Rule loading (valid YAML, invalid, unsupported features skipped)
- Regex evaluation (matches, non-matches, line numbers)
- Deduplication with built-in patterns
- Capability mapping from metadata
- CLI flags
- Bundled rule coverage
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from aegis.models.capabilities import (
    CapabilityCategory,
    Finding,
    FindingSeverity,
    ScopedCapability,
)
from aegis.scanner.semgrep_adapter import (
    SemgrepRule,
    _pattern_to_regex,
    deduplicate_findings,
    evaluate_semgrep_rules,
    load_semgrep_rules,
)


BUNDLED_RULES_DIR = Path(__file__).parent.parent / "aegis" / "rules" / "semgrep"


class TestRuleLoading:
    """Test loading Semgrep YAML rules."""

    def test_loads_bundled_rules(self):
        """Bundled rules directory should produce >0 rules."""
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        assert len(rules) > 20, f"Expected >20 bundled rules, got {len(rules)}"

    def test_valid_yaml_parsed(self, tmp_path):
        """A valid Semgrep YAML file should be parsed."""
        rule_yaml = {
            "rules": [{
                "id": "test-rule",
                "pattern-regex": r"eval\(",
                "message": "Do not use eval",
                "severity": "ERROR",
                "languages": ["python"],
            }]
        }
        (tmp_path / "test.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].id == "test-rule"
        assert rules[0].severity == FindingSeverity.PROHIBITED

    def test_invalid_yaml_skipped(self, tmp_path):
        """Invalid YAML should be skipped without crash."""
        (tmp_path / "bad.yaml").write_text("{{invalid yaml: [")
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 0

    def test_unsupported_features_skipped(self, tmp_path):
        """Rules with taint mode should be skipped."""
        rule_yaml = {
            "rules": [{
                "id": "taint-rule",
                "pattern-sources": [{"pattern": "get_input()"}],
                "pattern-sinks": [{"pattern": "exec($X)"}],
                "message": "Taint analysis",
                "severity": "ERROR",
                "languages": ["python"],
            }]
        }
        (tmp_path / "taint.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 0

    def test_missing_id_skipped(self, tmp_path):
        """Rules without an id should be skipped."""
        rule_yaml = {
            "rules": [{
                "pattern-regex": r"eval\(",
                "message": "no id",
                "severity": "ERROR",
                "languages": ["python"],
            }]
        }
        (tmp_path / "noid.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 0

    def test_invalid_regex_skipped(self, tmp_path):
        """Rules with invalid regex should be skipped."""
        rule_yaml = {
            "rules": [{
                "id": "bad-regex",
                "pattern-regex": r"[invalid(",
                "message": "bad regex",
                "severity": "ERROR",
                "languages": ["python"],
            }]
        }
        (tmp_path / "badregex.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 0

    def test_nonexistent_dir_returns_empty(self):
        """Non-existent directory should return empty list."""
        rules = load_semgrep_rules(Path("/nonexistent/path"))
        assert rules == []

    def test_severity_mapping(self, tmp_path):
        """ERROR → PROHIBITED, WARNING → RESTRICTED, INFO → RESTRICTED."""
        for sev, expected in [
            ("ERROR", FindingSeverity.PROHIBITED),
            ("WARNING", FindingSeverity.RESTRICTED),
            ("INFO", FindingSeverity.RESTRICTED),
        ]:
            rule_yaml = {
                "rules": [{
                    "id": f"sev-{sev.lower()}",
                    "pattern-regex": r"test_pattern",
                    "message": "test",
                    "severity": sev,
                    "languages": ["generic"],
                }]
            }
            (tmp_path / f"sev_{sev.lower()}.yaml").write_text(yaml.dump(rule_yaml))

        rules = load_semgrep_rules(tmp_path)
        sev_map = {r.id: r.severity for r in rules}
        assert sev_map["sev-error"] == FindingSeverity.PROHIBITED
        assert sev_map["sev-warning"] == FindingSeverity.RESTRICTED
        assert sev_map["sev-info"] == FindingSeverity.RESTRICTED

    def test_metadata_extraction(self, tmp_path):
        """CWE, OWASP, and aegis_capability should be extracted."""
        rule_yaml = {
            "rules": [{
                "id": "meta-test",
                "pattern-regex": r"dangerous_call\(",
                "message": "Found dangerous call",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata": {
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021"],
                    "aegis_capability": "network:connect",
                },
            }]
        }
        (tmp_path / "meta.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].cwe == ["CWE-89"]
        assert rules[0].owasp == ["A03:2021"]
        assert rules[0].aegis_capability == "network:connect"

    def test_pattern_either_loaded(self, tmp_path):
        """pattern-either with multiple regexes should create multiple patterns."""
        rule_yaml = {
            "rules": [{
                "id": "either-test",
                "pattern-either": [
                    {"pattern-regex": r"eval\("},
                    {"pattern-regex": r"exec\("},
                ],
                "message": "Found eval or exec",
                "severity": "ERROR",
                "languages": ["python"],
            }]
        }
        (tmp_path / "either.yaml").write_text(yaml.dump(rule_yaml))
        rules = load_semgrep_rules(tmp_path)
        assert len(rules) == 1
        assert len(rules[0].regex_patterns) == 2


class TestPatternToRegex:
    """Test conversion of simple Semgrep patterns to regex."""

    def test_func_with_ellipsis(self):
        """eval(...) → \\beval\\s*\\("""
        result = _pattern_to_regex("eval(...)")
        assert result is not None
        import re
        assert re.search(result, "eval('code')")

    def test_dotted_func(self):
        """os.system(...) → \\bos\\.system\\s*\\("""
        result = _pattern_to_regex("os.system(...)")
        assert result is not None
        import re
        assert re.search(result, "os.system('ls')")

    def test_metavar_func(self):
        """$X.innerHTML = ... → \\.innerHTML\\s*="""
        result = _pattern_to_regex("$X.innerHTML = $Y")
        assert result is not None
        import re
        assert re.search(result, 'elem.innerHTML = userInput')

    def test_complex_returns_none(self):
        """Complex patterns should return None."""
        result = _pattern_to_regex("if $X: ...\n  $Y.call()")
        assert result is None


class TestRuleEvaluation:
    """Test regex evaluation against source files."""

    def _make_rule(self, rule_id, pattern, severity="WARNING", languages=None, aegis_cap=None):
        import re
        return SemgrepRule(
            id=rule_id,
            regex_patterns=[re.compile(pattern)],
            message=f"Test rule: {rule_id}",
            severity=_severity(severity),
            languages=languages or ["python"],
            aegis_capability=aegis_cap,
        )

    def test_matches_correct_line(self, tmp_path):
        """Findings should have correct line numbers."""
        code = "x = 1\neval('code')\nprint('done')\n"
        py_file = tmp_path / "test.py"
        py_file.write_text(code)

        rules = [self._make_rule("test-eval", r"\beval\s*\(", "ERROR")]
        prohibited, restricted, caps = evaluate_semgrep_rules(
            py_file, "test.py", code, "python", rules
        )
        assert len(prohibited) == 1
        assert prohibited[0].line == 2

    def test_non_matching_file(self, tmp_path):
        """No findings for clean code."""
        code = "x = 1\nprint('hello')\n"
        py_file = tmp_path / "test.py"
        py_file.write_text(code)

        rules = [self._make_rule("test-eval", r"\beval\s*\(")]
        _, restricted, _ = evaluate_semgrep_rules(
            py_file, "test.py", code, "python", rules
        )
        assert len(restricted) == 0

    def test_language_filter(self, tmp_path):
        """Rules should only match files of the right language."""
        code = "eval('code')\n"
        js_file = tmp_path / "test.js"
        js_file.write_text(code)

        rules = [self._make_rule("py-only", r"\beval\s*\(", languages=["python"])]
        prohibited, restricted, _ = evaluate_semgrep_rules(
            js_file, "test.js", code, "javascript", rules
        )
        assert len(prohibited) == 0
        assert len(restricted) == 0

    def test_generic_language_matches_all(self, tmp_path):
        """Rules with 'generic' language should match any file."""
        code = "AKIA0123456789ABCDEF\n"
        txt_file = tmp_path / "test.txt"
        txt_file.write_text(code)

        import re
        rule = SemgrepRule(
            id="aws-key",
            regex_patterns=[re.compile(r"AKIA[0-9A-Z]{16}")],
            message="AWS key detected",
            severity=FindingSeverity.PROHIBITED,
            languages=["generic"],
        )
        prohibited, _, _ = evaluate_semgrep_rules(
            txt_file, "test.txt", code, "generic", [rule]
        )
        assert len(prohibited) == 1

    def test_capability_mapping(self, tmp_path):
        """aegis_capability in metadata should produce ScopedCapability."""
        code = "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
        py_file = tmp_path / "test.py"
        py_file.write_text(code)

        rules = [self._make_rule(
            "sql-injection",
            r"cursor\.execute\s*\(\s*f",
            "ERROR",
            aegis_cap="network:connect",
        )]
        prohibited, _, caps = evaluate_semgrep_rules(
            py_file, "test.py", code, "python", rules
        )
        assert len(caps) > 0
        assert any(c.capability_key == "network:connect" for c in caps)

    def test_cwe_owasp_in_message(self, tmp_path):
        """CWE/OWASP references should appear in finding message."""
        code = "eval('hack')\n"
        py_file = tmp_path / "test.py"
        py_file.write_text(code)

        import re as re_mod
        rule = SemgrepRule(
            id="with-cwe",
            regex_patterns=[re_mod.compile(r"\beval\s*\(")],
            message="Dangerous eval",
            severity=FindingSeverity.PROHIBITED,
            languages=["python"],
            cwe=["CWE-95"],
            owasp=["A03:2021"],
        )
        prohibited, _, _ = evaluate_semgrep_rules(
            py_file, "test.py", code, "python", [rule]
        )
        assert len(prohibited) == 1
        assert "CWE-95" in prohibited[0].message
        assert "A03:2021" in prohibited[0].message


class TestDeduplication:
    """Test deduplication of Aegis vs Semgrep findings."""

    def test_same_line_prefers_aegis(self):
        """If Aegis already flagged a line, Semgrep finding is dropped."""
        aegis = [Finding(file="test.py", line=5, pattern="eval", severity=FindingSeverity.PROHIBITED, message="")]
        semgrep = [Finding(file="test.py", line=5, pattern="semgrep:test", severity=FindingSeverity.RESTRICTED, message="")]
        unique = deduplicate_findings(aegis, semgrep)
        assert len(unique) == 0

    def test_different_line_kept(self):
        """Semgrep finding on a different line should be kept."""
        aegis = [Finding(file="test.py", line=5, pattern="eval", severity=FindingSeverity.PROHIBITED, message="")]
        semgrep = [Finding(file="test.py", line=10, pattern="semgrep:test", severity=FindingSeverity.RESTRICTED, message="")]
        unique = deduplicate_findings(aegis, semgrep)
        assert len(unique) == 1

    def test_different_file_kept(self):
        """Semgrep finding in a different file should be kept."""
        aegis = [Finding(file="a.py", line=5, pattern="eval", severity=FindingSeverity.PROHIBITED, message="")]
        semgrep = [Finding(file="b.py", line=5, pattern="semgrep:test", severity=FindingSeverity.RESTRICTED, message="")]
        unique = deduplicate_findings(aegis, semgrep)
        assert len(unique) == 1


class TestBundledRuleCoverage:
    """Verify bundled rules fire on known-bad patterns."""

    def _run_rules_on_code(self, code: str, filename: str = "test.py", lang: str = "python"):
        rules = load_semgrep_rules(BUNDLED_RULES_DIR)
        return evaluate_semgrep_rules(
            Path(filename), filename, code, lang, rules
        )

    def test_python_sql_injection(self):
        code = "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
        prohibited, restricted, _ = self._run_rules_on_code(code)
        all_findings = prohibited + restricted
        assert any("sql" in f.pattern.lower() or "sql" in f.message.lower() for f in all_findings)

    def test_aws_access_key_detected(self):
        code = 'key = "AKIAIOSFODNN7EXAMPLE"\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "config.py", "python")
        all_findings = prohibited + restricted
        assert any("aws" in f.pattern.lower() for f in all_findings)

    def test_github_pat_detected(self):
        code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "config.py", "python")
        all_findings = prohibited + restricted
        assert any("github" in f.pattern.lower() for f in all_findings)

    def test_stripe_key_detected(self):
        code = 'key = "sk_live_ABC123DEF456GHI789JKL012MNO"\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "config.py", "python")
        all_findings = prohibited + restricted
        assert any("stripe" in f.pattern.lower() for f in all_findings)

    def test_private_key_detected(self):
        code = 'key = "-----BEGIN RSA PRIVATE KEY-----"\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "config.py", "python")
        all_findings = prohibited + restricted
        assert any("private" in f.pattern.lower() or "private" in f.message.lower() for f in all_findings)

    def test_js_innerhtml_detected(self):
        code = 'element.innerHTML = userInput;\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "app.js", "javascript")
        all_findings = prohibited + restricted
        assert any("innerhtml" in f.pattern.lower() or "xss" in f.message.lower() for f in all_findings)

    def test_js_eval_detected(self):
        code = 'eval(userInput);\n'
        prohibited, restricted, _ = self._run_rules_on_code(code, "app.js", "javascript")
        all_findings = prohibited + restricted
        assert any("eval" in f.pattern.lower() for f in all_findings)

    def test_clean_code_no_findings(self):
        code = "x = 1\ny = x + 2\nprint(y)\n"
        prohibited, restricted, _ = self._run_rules_on_code(code)
        assert len(prohibited) == 0
        assert len(restricted) == 0


def _severity(s: str) -> FindingSeverity:
    return {"ERROR": FindingSeverity.PROHIBITED, "WARNING": FindingSeverity.RESTRICTED,
            "INFO": FindingSeverity.RESTRICTED}[s]
