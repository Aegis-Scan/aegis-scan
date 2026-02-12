"""Tests for the hardcoded secret scanner."""

from pathlib import Path

import pytest

from aegis.models.capabilities import CapabilityCategory, FindingSeverity
from aegis.scanner.secret_scanner import (
    _check_connection_string,
    _check_known_key_pattern,
    _is_high_entropy_secret,
    _is_placeholder,
    _shannon_entropy,
    scan_python_secrets,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        assert _shannon_entropy("aB3$xZ9!mN") > 3.0

    def test_low_entropy(self):
        assert _shannon_entropy("aaabbb") < 2.0


class TestIsPlaceholder:
    def test_empty_string(self):
        assert _is_placeholder("") is True

    def test_todo(self):
        assert _is_placeholder("TODO") is True

    def test_changeme(self):
        assert _is_placeholder("CHANGEME") is True

    def test_angle_brackets(self):
        assert _is_placeholder("<your_key>") is True

    def test_env_var_placeholder(self):
        assert _is_placeholder("${API_KEY}") is True

    def test_jinja_placeholder(self):
        assert _is_placeholder("{{secret}}") is True

    def test_real_value_not_placeholder(self):
        assert _is_placeholder("sk_live_abc123def456ghi789") is False


class TestKnownKeyPatterns:
    def test_aws_access_key(self):
        result = _check_known_key_pattern("AKIAIOSFODNN7EXAMPLE")
        assert result is not None
        assert "AWS" in result

    def test_github_pat(self):
        result = _check_known_key_pattern("ghp_ABCDEFabcdef1234567890abcdef12345678")
        assert result is not None
        assert "GitHub" in result

    def test_stripe_live_key(self):
        result = _check_known_key_pattern("sk_live_abcdefghijklmnopqrstuvwx")
        assert result is not None
        assert "Stripe" in result

    def test_slack_token(self):
        result = _check_known_key_pattern("xoxb-123456-789012-abcdef")
        assert result is not None
        assert "Slack" in result

    def test_jwt(self):
        # Minimal JWT structure
        result = _check_known_key_pattern(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        )
        assert result is not None
        assert "JWT" in result or "Web Token" in result

    def test_random_string_no_match(self):
        assert _check_known_key_pattern("hello_world") is None

    def test_short_string_no_match(self):
        assert _check_known_key_pattern("abc") is None


class TestConnectionString:
    def test_postgres_with_password(self):
        result = _check_connection_string(
            "postgres://admin:s3cur3p@ss@db.example.com:5432/mydb"
        )
        assert result is not None
        assert "postgres" in result

    def test_mysql_with_password(self):
        result = _check_connection_string(
            "mysql://root:hunter2@localhost/testdb"
        )
        assert result is not None

    def test_mongodb_with_password(self):
        result = _check_connection_string(
            "mongodb+srv://user:s3cur3pass@cluster.mongodb.net/db"
        )
        assert result is not None

    def test_redis_with_password(self):
        result = _check_connection_string(
            "redis://default:secretpass@redis.example.com:6379/0"
        )
        assert result is not None

    def test_placeholder_password_ignored(self):
        result = _check_connection_string(
            "postgres://admin:changeme@localhost/db"
        )
        assert result is None

    def test_no_credentials(self):
        result = _check_connection_string("https://example.com/api")
        assert result is None


class TestHighEntropySecret:
    def test_short_string_rejected(self):
        assert _is_high_entropy_secret("abc") is False

    def test_low_entropy_rejected(self):
        assert _is_high_entropy_secret("a" * 30) is False

    def test_real_looking_secret(self):
        # Mix of upper, lower, digits, high entropy
        assert _is_high_entropy_secret("aB3xZ9mNpQ7rT5wY1kL2") is True

    def test_all_same_char_type(self):
        # Only lowercase, low char type diversity
        assert _is_high_entropy_secret("abcdefghijklmnopqrstu") is False


class TestScanPythonSecrets:
    """Integration tests using tmp_path to create Python files."""

    def test_detects_password_assignment(self, tmp_path: Path):
        script = tmp_path / "creds.py"
        script.write_text('password = "hunter2rocks"\n')
        findings, caps = scan_python_secrets(script, "creds.py")
        assert len(findings) >= 1
        assert findings[0].severity == FindingSeverity.RESTRICTED
        assert findings[0].capability.category == CapabilityCategory.SECRET
        assert "password" in findings[0].pattern

    def test_detects_api_key_assignment(self, tmp_path: Path):
        script = tmp_path / "config.py"
        script.write_text('API_KEY = "sk_live_abcdefghijklmnopqrstuvwx"\n')
        findings, caps = scan_python_secrets(script, "config.py")
        assert len(findings) >= 1
        # Should match either the name pattern or the Stripe key pattern
        assert any("secret" in f.pattern or "key" in f.pattern.lower() or "Stripe" in f.message
                    for f in findings)

    def test_detects_aws_key(self, tmp_path: Path):
        script = tmp_path / "aws.py"
        script.write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings, caps = scan_python_secrets(script, "aws.py")
        assert len(findings) >= 1
        assert any("AWS" in f.message for f in findings)

    def test_detects_github_pat(self, tmp_path: Path):
        script = tmp_path / "gh.py"
        script.write_text('token = "ghp_ABCDEFabcdef1234567890abcdef12345678"\n')
        findings, caps = scan_python_secrets(script, "gh.py")
        assert len(findings) >= 1
        # Detected via variable name 'token' or known GitHub PAT pattern
        assert any("token" in f.pattern or "GitHub" in f.message for f in findings)

    def test_detects_connection_string(self, tmp_path: Path):
        script = tmp_path / "db.py"
        script.write_text(
            'DATABASE_URL = "postgres://admin:s3cur3p@ss@db.example.com:5432/mydb"\n'
        )
        findings, caps = scan_python_secrets(script, "db.py")
        assert len(findings) >= 1
        assert any("connection_string" in f.pattern for f in findings)

    def test_ignores_placeholder(self, tmp_path: Path):
        script = tmp_path / "placeholder.py"
        script.write_text('password = "CHANGEME"\n')
        findings, caps = scan_python_secrets(script, "placeholder.py")
        assert len(findings) == 0

    def test_ignores_empty_value(self, tmp_path: Path):
        script = tmp_path / "empty.py"
        script.write_text('password = ""\n')
        findings, caps = scan_python_secrets(script, "empty.py")
        assert len(findings) == 0

    def test_ignores_short_value(self, tmp_path: Path):
        script = tmp_path / "short.py"
        script.write_text('password = "ab"\n')
        findings, caps = scan_python_secrets(script, "short.py")
        assert len(findings) == 0

    def test_detects_keyword_arg_secret(self, tmp_path: Path):
        script = tmp_path / "call.py"
        script.write_text('connect(password="realpassword123")\n')
        findings, caps = scan_python_secrets(script, "call.py")
        assert len(findings) >= 1

    def test_clean_file_no_findings(self, tmp_path: Path):
        script = tmp_path / "clean.py"
        script.write_text(
            'import os\n\ndef hello():\n    return "Hello, world!"\n'
        )
        findings, caps = scan_python_secrets(script, "clean.py")
        assert len(findings) == 0

    def test_syntax_error_no_crash(self, tmp_path: Path):
        script = tmp_path / "bad.py"
        script.write_text("def broken(\n")
        findings, caps = scan_python_secrets(script, "bad.py")
        assert len(findings) == 0

    def test_nonexistent_file_no_crash(self, tmp_path: Path):
        findings, caps = scan_python_secrets(
            tmp_path / "nope.py", "nope.py"
        )
        assert len(findings) == 0

    def test_capability_scope_is_hardcoded(self, tmp_path: Path):
        script = tmp_path / "creds.py"
        script.write_text('secret = "real_secret_value"\n')
        findings, caps = scan_python_secrets(script, "creds.py")
        assert len(caps) >= 1
        assert caps[0].scope == ["hardcoded"]
        assert caps[0].scope_resolved is True

    def test_detects_jwt_in_string(self, tmp_path: Path):
        script = tmp_path / "jwt_test.py"
        script.write_text(
            'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"\n'
        )
        findings, caps = scan_python_secrets(script, "jwt_test.py")
        assert len(findings) >= 1
        # Detected via variable name 'token' or JWT pattern
        assert any("token" in f.pattern or "JWT" in f.message or "Web Token" in f.message
                    for f in findings)
