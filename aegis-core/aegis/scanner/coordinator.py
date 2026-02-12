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

"""File walker — discovers files to scan using git or directory fallback.

Primary strategy: git ls-files (if .git/ exists)
Fallback: recursive directory walk with .aegisignore support
Records manifest_source ("git" or "directory") in output.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Default patterns to ignore when using directory walk fallback
DEFAULT_IGNORE_PATTERNS = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "*.egg-info",
    ".eggs",
    "*.pyc",
    "*.pyo",
    "*.so",
    "*.dylib",
    "*.dll",
    # Aegis's own output files — scanning these creates self-referential false positives
    "aegis_report.json",
    "aegis.lock",
}

# File extensions to scan for Python source code (AST analysis)
PYTHON_EXTENSIONS = {".py"}

# File extensions to scan for shell script analysis
SHELL_EXTENSIONS = {".sh", ".bat", ".ps1", ".bash", ".zsh", ".fish"}

# File extensions to scan for JavaScript/TypeScript analysis
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

# File extensions to scan for config/data analysis
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".cfg", ".ini"}

# Dockerfile names (case-insensitive matching done in get_dockerfiles)
DOCKERFILE_NAMES = {
    "dockerfile", "dockerfile.dev", "dockerfile.prod",
    "dockerfile.staging", "dockerfile.test", "containerfile",
}
DOCKERFILE_EXTENSIONS = {".dockerfile"}

# NOTE: The manifest now includes ALL discovered files (not just a curated list).
# This ensures every file in the skill directory is hashed and attested in the
# lockfile. Unwanted files can be excluded via .aegisignore.


def _load_aegisignore(target_dir: Path) -> set[str]:
    """Load .aegisignore patterns from the target directory."""
    ignore_file = target_dir / ".aegisignore"
    patterns = set(DEFAULT_IGNORE_PATTERNS)

    if ignore_file.exists():
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.add(line)

    return patterns


def _should_ignore(path: Path, ignore_patterns: set[str]) -> bool:
    """Check if a path matches any ignore pattern."""
    for pattern in ignore_patterns:
        if pattern.startswith("*"):
            # Glob-style suffix matching
            suffix = pattern.lstrip("*")
            if path.name.endswith(suffix) or str(path).endswith(suffix):
                return True
        elif path.name == pattern or pattern in path.parts:
            return True
    return False


def get_files_git(target_dir: Path) -> list[Path] | None:
    """Get tracked files using git ls-files.

    Returns None if git is not available or target_dir is not a git repo.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.debug("git ls-files failed: %s", result.stderr)
            return None

        files = []
        for line in result.stdout.strip().splitlines():
            if line:
                file_path = Path(line)
                files.append(file_path)

        return sorted(files)

    except FileNotFoundError:
        logger.debug("git not found in PATH")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("git ls-files timed out")
        return None
    except Exception as e:
        logger.debug("git ls-files error: %s", e)
        return None


def get_files_directory(target_dir: Path) -> list[Path]:
    """Get files via recursive directory walk with .aegisignore.

    Fallback when git is not available.
    """
    ignore_patterns = _load_aegisignore(target_dir)
    files = []

    for item in sorted(target_dir.rglob("*")):
        if item.is_file():
            rel_path = item.relative_to(target_dir)
            if not _should_ignore(rel_path, ignore_patterns):
                files.append(rel_path)

    return sorted(files)


def get_python_files(all_files: list[Path]) -> list[Path]:
    """Filter to only Python source files (for AST analysis)."""
    return [f for f in all_files if f.suffix in PYTHON_EXTENSIONS]


def get_shell_files(all_files: list[Path]) -> list[Path]:
    """Filter to shell script files (for shell analysis)."""
    return [f for f in all_files if f.suffix in SHELL_EXTENSIONS]


def get_js_files(all_files: list[Path]) -> list[Path]:
    """Filter to JavaScript/TypeScript files (for JS analysis)."""
    return [f for f in all_files if f.suffix in JS_EXTENSIONS]


def get_config_files(all_files: list[Path]) -> list[Path]:
    """Filter to config/data files (for config analysis)."""
    return [f for f in all_files if f.suffix in CONFIG_EXTENSIONS]


def get_dockerfiles(all_files: list[Path]) -> list[Path]:
    """Filter to Dockerfile-like files."""
    result = []
    for f in all_files:
        name_lower = f.name.lower()
        if name_lower in DOCKERFILE_NAMES or name_lower.startswith("dockerfile."):
            result.append(f)
        elif f.suffix.lower() in DOCKERFILE_EXTENSIONS:
            result.append(f)
    return result


def get_manifest_files(all_files: list[Path]) -> list[Path]:
    """Return all discovered files for the manifest (hashing).

    All files are included — the manifest covers the entire skill directory.
    Filtering is handled upstream by .aegisignore and ignore patterns.
    """
    return list(all_files)


def discover_files(target_dir: Path) -> tuple[list[Path], str]:
    """Discover files to scan.

    Returns:
        tuple of (files, manifest_source) where manifest_source is
        "git" or "directory".
    """
    target_dir = target_dir.resolve()

    if not target_dir.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

    if not target_dir.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_dir}")

    # Try git first
    git_dir = target_dir / ".git"
    if git_dir.exists():
        files = get_files_git(target_dir)
        if files is not None:
            logger.info("Using git-derived manifest (%d files)", len(files))
            return files, "git"

    # Fallback to directory walk
    files = get_files_directory(target_dir)
    logger.info("Using directory walk manifest (%d files)", len(files))
    return files, "directory"
