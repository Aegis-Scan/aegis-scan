"""Tests for the steganography (hidden character) scanner."""

from pathlib import Path

import pytest

from aegis.models.capabilities import FindingSeverity
from aegis.scanner.steganography_scanner import scan_file_steganography


class TestZeroWidthDetection:
    """Detect invisible zero-width characters in source files."""

    def test_zero_width_space(self, tmp_path: Path):
        """U+200B (zero-width space) should be flagged as PROHIBITED."""
        f = tmp_path / "sneaky.py"
        f.write_text("x = 1\u200B\ny = 2\n", encoding="utf-8")
        findings = scan_file_steganography(f, "sneaky.py")
        assert len(findings) >= 1
        assert findings[0].severity == FindingSeverity.PROHIBITED
        assert "steganography:zero_width" in findings[0].pattern

    def test_zero_width_joiner(self, tmp_path: Path):
        """U+200D (zero-width joiner) should be flagged."""
        f = tmp_path / "zjoiner.py"
        f.write_text("data = 'hello\u200Dworld'\n", encoding="utf-8")
        findings = scan_file_steganography(f, "zjoiner.py")
        assert len(findings) >= 1
        assert "invisible" in findings[0].message.lower()

    def test_feff_byte_order_mark_at_start_ignored(self, tmp_path: Path):
        """BOM (U+FEFF) at position 0 is normal and should NOT be flagged."""
        f = tmp_path / "bom.py"
        f.write_text("\uFEFFx = 1\n", encoding="utf-8")
        findings = scan_file_steganography(f, "bom.py")
        assert len(findings) == 0

    def test_feff_not_at_start_flagged(self, tmp_path: Path):
        """BOM (U+FEFF) in the middle of a file IS suspicious."""
        f = tmp_path / "mid_bom.py"
        f.write_text("x = 1\ny = '\uFEFF'\n", encoding="utf-8")
        findings = scan_file_steganography(f, "mid_bom.py")
        assert len(findings) >= 1

    def test_multiple_zero_width_chars(self, tmp_path: Path):
        """Multiple different invisible chars should produce a single finding."""
        f = tmp_path / "multi.py"
        f.write_text("a\u200B = b\u200C + c\u200D\n", encoding="utf-8")
        findings = scan_file_steganography(f, "multi.py")
        # Should be exactly 1 consolidated finding
        zwc_findings = [f for f in findings if f.pattern == "steganography:zero_width"]
        assert len(zwc_findings) == 1
        assert "3" in zwc_findings[0].message  # 3 invisible characters

    def test_clean_file_no_findings(self, tmp_path: Path):
        """Normal Python file should produce no findings."""
        f = tmp_path / "clean.py"
        f.write_text("def hello():\n    return 'world'\n", encoding="utf-8")
        findings = scan_file_steganography(f, "clean.py")
        assert len(findings) == 0

    def test_binary_file_skipped(self, tmp_path: Path):
        """Binary files should be silently skipped."""
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_file_steganography(f, "image.png")
        assert len(findings) == 0

    def test_empty_file_no_findings(self, tmp_path: Path):
        """Empty file should produce no findings."""
        f = tmp_path / "empty.py"
        f.write_text("", encoding="utf-8")
        findings = scan_file_steganography(f, "empty.py")
        assert len(findings) == 0


class TestHomoglyphDetection:
    """Detect Cyrillic/Greek characters that look like Latin in source code."""

    def test_cyrillic_a_in_python(self, tmp_path: Path):
        """Cyrillic 'а' (U+0430) in Python should be flagged."""
        f = tmp_path / "homoglyph.py"
        # The 'а' below is Cyrillic U+0430, not Latin 'a'
        f.write_text("p\u0430ssword = 'secret'\n", encoding="utf-8")
        findings = scan_file_steganography(f, "homoglyph.py")
        homo_findings = [f for f in findings if f.pattern == "steganography:homoglyph"]
        assert len(homo_findings) == 1
        assert "homoglyph" in homo_findings[0].message.lower()

    def test_cyrillic_in_non_source_file(self, tmp_path: Path):
        """Cyrillic in non-source files should not trigger homoglyph detection."""
        f = tmp_path / "readme.md"
        # Markdown with Cyrillic is fine
        f.write_text("# Привет мир\n", encoding="utf-8")
        findings = scan_file_steganography(f, "readme.md")
        homo_findings = [f for f in findings if f.pattern == "steganography:homoglyph"]
        assert len(homo_findings) == 0

    def test_clean_source_no_homoglyphs(self, tmp_path: Path):
        """Normal ASCII source code has no homoglyph findings."""
        f = tmp_path / "clean.py"
        f.write_text("password = 'secret'\n", encoding="utf-8")
        findings = scan_file_steganography(f, "clean.py")
        homo_findings = [f for f in findings if f.pattern == "steganography:homoglyph"]
        assert len(homo_findings) == 0
