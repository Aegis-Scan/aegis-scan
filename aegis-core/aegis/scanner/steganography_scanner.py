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

"""Steganography scanner — detects hidden/invisible characters in source files.

AI models can embed zero-width characters (ZWCs) in generated code for:
- Data exfiltration (encoding secrets in invisible Unicode)
- Watermarking (tracking code provenance via hidden bits)
- Payload smuggling (invisible strings that resolve at runtime)

This scanner flags any source file containing suspicious Unicode ranges:
- U+200B  Zero Width Space
- U+200C  Zero Width Non-Joiner
- U+200D  Zero Width Joiner
- U+200E  Left-to-Right Mark
- U+200F  Right-to-Left Mark
- U+2060  Word Joiner
- U+2061  Function Application (invisible math)
- U+2062  Invisible Times
- U+2063  Invisible Separator
- U+2064  Invisible Plus
- U+FEFF  Byte Order Mark (when not at position 0)
- U+00AD  Soft Hyphen
- U+034F  Combining Grapheme Joiner
- U+180E  Mongolian Vowel Separator (deprecated space)
- Homoglyph confusables (Cyrillic/Greek letters that look like Latin)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from aegis.models.capabilities import (
    Finding,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# Zero-width and invisible character pattern
_ZERO_WIDTH_PATTERN = re.compile(
    r"[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u034F\u180E]"
)

# Homoglyph confusables: Cyrillic/Greek letters commonly confused with Latin.
# These are legitimate in natural-language text but suspicious in source code.
_HOMOGLYPH_PATTERN = re.compile(
    r"[\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425"  # Cyrillic caps (А В Е К М Н О Р С Т Х)
    r"\u0430\u0435\u043E\u0440\u0441\u0445"  # Cyrillic lower (а е о р с х)
    r"\u0391\u0392\u0395\u0396\u0397\u0399\u039A\u039C\u039D\u039F\u03A1\u03A4\u03A5\u03A7"  # Greek caps
    r"\u03BF\u03C1]"  # Greek lower (ο ρ)
)

# Binary / non-text file extensions to skip
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".whl", ".egg", ".pyc", ".pyo", ".so", ".dll", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".lock", ".lockb",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
})


def scan_file_steganography(
    file_path: Path,
    relative_name: str,
) -> list[Finding]:
    """Scan a single file for hidden/invisible characters.

    Returns a list of PROHIBITED findings (one per unique hidden-char type found).
    """
    # Skip binary files
    if file_path.suffix.lower() in _BINARY_EXTENSIONS:
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return []

    if not content:
        return []

    findings: list[Finding] = []

    # ── Zero-width / invisible character scan ──
    zwc_matches = list(_ZERO_WIDTH_PATTERN.finditer(content))
    if zwc_matches:
        # Find line numbers for first few occurrences
        lines = content.splitlines()
        hit_lines: list[int] = []
        char_pos = 0
        line_idx = 0
        match_idx = 0

        for line_idx, line_text in enumerate(lines, start=1):
            line_end = char_pos + len(line_text) + 1  # +1 for newline
            while match_idx < len(zwc_matches) and zwc_matches[match_idx].start() < line_end:
                # Skip BOM at position 0 (that's normal)
                if zwc_matches[match_idx].start() == 0 and zwc_matches[match_idx].group() == "\uFEFF":
                    match_idx += 1
                    continue
                hit_lines.append(line_idx)
                match_idx += 1
            char_pos = line_end
            if match_idx >= len(zwc_matches):
                break

        # Filter out BOM-only matches
        non_bom_count = len(zwc_matches)
        if content.startswith("\uFEFF"):
            non_bom_count -= 1

        if non_bom_count > 0:
            first_line = hit_lines[0] if hit_lines else 1
            unique_chars = set(m.group() for m in zwc_matches)
            # Don't count BOM at position 0
            if content.startswith("\uFEFF"):
                unique_chars.discard("\uFEFF")

            char_names = ", ".join(
                f"U+{ord(c):04X}" for c in sorted(unique_chars, key=ord)
            )
            findings.append(
                Finding(
                    file=relative_name,
                    line=first_line,
                    col=0,
                    pattern="steganography:zero_width",
                    severity=FindingSeverity.PROHIBITED,
                    message=(
                        f"Hidden characters detected: {non_bom_count} invisible "
                        f"character(s) ({char_names}) across {len(hit_lines)} line(s). "
                        "Possible data exfiltration, watermarking, or payload smuggling."
                    ),
                )
            )

    # ── Homoglyph confusable scan (source code files only) ──
    source_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".sh", ".bash", ".bat", ".ps1", ".zsh",
        ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".h",
        ".yaml", ".yml", ".toml", ".json", ".cfg", ".ini",
    }
    if file_path.suffix.lower() in source_extensions:
        homoglyph_matches = list(_HOMOGLYPH_PATTERN.finditer(content))
        if homoglyph_matches:
            # Find line number of first match
            first_pos = homoglyph_matches[0].start()
            first_line = content[:first_pos].count("\n") + 1

            unique_chars = set(m.group() for m in homoglyph_matches)
            char_names = ", ".join(
                f"U+{ord(c):04X} ('{c}')" for c in sorted(unique_chars, key=ord)
            )
            findings.append(
                Finding(
                    file=relative_name,
                    line=first_line,
                    col=0,
                    pattern="steganography:homoglyph",
                    severity=FindingSeverity.RESTRICTED,
                    message=(
                        f"Homoglyph confusables: {len(homoglyph_matches)} non-Latin "
                        f"character(s) ({char_names}) that visually mimic ASCII. "
                        "Possible identifier spoofing or obfuscation."
                    ),
                )
            )

    return findings
