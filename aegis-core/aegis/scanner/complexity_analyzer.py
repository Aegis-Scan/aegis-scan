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

"""Cyclomatic complexity analyzer for Python source files.

Computes per-function cyclomatic complexity (CC) using AST analysis.
Functions with CC > threshold are flagged as RESTRICTED findings, since
high complexity correlates with vulnerability density — deeply nested
logic often hides "dead zones" where security checks are bypassed or
exceptions are swallowed silently.

Reference: Section 7.3 of "Deep Static Analysis of Python Standard Library
Vulnerabilities: An AST-Centric Taxonomy for Legacy Monolith Audits".
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from aegis.models.capabilities import (
    Finding,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# Default threshold — functions above this are flagged
DEFAULT_COMPLEXITY_THRESHOLD = 15


class _ComplexityVisitor(ast.NodeVisitor):
    """Count branching nodes to compute cyclomatic complexity."""

    def __init__(self) -> None:
        self.complexity = 1  # Base complexity

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each `and`/`or` adds a decision point
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        # Ternary expression (a if cond else b)
        self.complexity += 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        # Each for + each if in comprehension
        self.complexity += 1
        self.complexity += len(node.ifs)
        self.generic_visit(node)


def _compute_function_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Compute cyclomatic complexity for a single function/method."""
    visitor = _ComplexityVisitor()
    visitor.visit(node)
    return visitor.complexity


class _FunctionFinder(ast.NodeVisitor):
    """Find all function and method definitions in a module."""

    def __init__(self) -> None:
        self.functions: list[tuple[str, int, int]] = []  # (name, line, complexity)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        cc = _compute_function_complexity(node)
        self.functions.append((node.name, node.lineno, cc))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        cc = _compute_function_complexity(node)
        self.functions.append((node.name, node.lineno, cc))
        self.generic_visit(node)


def analyze_complexity(
    file_path: Path,
    relative_name: str,
    threshold: int = DEFAULT_COMPLEXITY_THRESHOLD,
) -> list[Finding]:
    """Analyze a Python file for functions with high cyclomatic complexity.

    Args:
        file_path: Absolute path to the Python file.
        relative_name: Relative display name for findings.
        threshold: CC threshold above which to flag functions.

    Returns:
        List of RESTRICTED findings for overly complex functions.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        logger.warning("Could not read %s: %s", file_path, e)
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        logger.warning("Syntax error in %s: %s", file_path, e)
        return []

    finder = _FunctionFinder()
    finder.visit(tree)

    findings: list[Finding] = []
    for func_name, line, cc in finder.functions:
        if cc > threshold:
            findings.append(
                Finding(
                    file=relative_name,
                    line=line,
                    col=0,
                    pattern=f"high_complexity:{func_name}",
                    severity=FindingSeverity.RESTRICTED,
                    message=(
                        f"Function '{func_name}' has cyclomatic complexity {cc} "
                        f"(threshold: {threshold}). High complexity correlates with "
                        f"vulnerability density — consider refactoring."
                    ),
                )
            )

    return findings
