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

"""Pydantic models for the scan report (dual-payload: deterministic + ephemeral)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from aegis import __version__
from aegis.models.capabilities import (
    CombinationRisk,
    Finding,
    MetaInsight,
    PersonaClassification,
    ScopedCapability,
)


class MerkleLeaf(BaseModel):
    """A single file leaf in the Merkle tree."""

    path: str
    hash: str  # "sha256:xxxx..."


class MerkleTree(BaseModel):
    """The full lazy Merkle tree structure.

    Stores all leaves and intermediate nodes to enable both full
    verification and single-file proof verification.
    """

    root: str  # "sha256:xxxx..."
    algorithm: str = "sha256"
    leaves: list[MerkleLeaf] = Field(default_factory=list)
    nodes: list[str] = Field(default_factory=list)  # intermediate node hashes


class RiskScore(BaseModel):
    """Three-part risk score: static (signed), llm_adjustment (ephemeral), final."""

    static: int = 0
    llm_adjustment: int = 0
    final: int = 0


class UnresolvedScopeAnalysis(BaseModel):
    """LLM analysis of an unresolved scope."""

    file: str
    line: int
    llm_opinion: str


class DeterministicPayload(BaseModel):
    """Deterministic scan results — reproducible, signable."""

    manifest_source: str = "git"  # "git" or "directory"
    file_count: int = 0
    merkle_tree: MerkleTree = Field(default_factory=MerkleTree)
    capabilities: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    external_binaries: list[str] = Field(default_factory=list)
    prohibited_findings: list[Finding] = Field(default_factory=list)
    restricted_findings: list[Finding] = Field(default_factory=list)
    combination_risks: list[CombinationRisk] = Field(default_factory=list)
    path_violations: list[dict[str, Any]] = Field(default_factory=list)
    meta_insights: list[MetaInsight] = Field(default_factory=list)
    persona: Optional[PersonaClassification] = None
    remediation_feedback: Optional[dict[str, Any]] = None
    risk_score_static: int = 0


class TaxonomyPayload(BaseModel):
    """Taxonomy classification and permission-overreach (from SKILL.md + code)."""

    skill_category: str = "general"
    classification_confidence: str = "none"
    permission_overreach: list[str] = Field(default_factory=list)
    tool_overreach: list[str] = Field(default_factory=list)


class EphemeralPayload(BaseModel):
    """Ephemeral scan results — LLM-dependent, not signed."""

    llm_provider: Optional[str] = None
    llm_analysis: Optional[str] = None
    llm_risk_adjustment: int = 0
    risk_score_final: int = 0
    unresolved_scope_analysis: list[UnresolvedScopeAnalysis] = Field(
        default_factory=list
    )
    taxonomy: Optional[TaxonomyPayload] = None


class ScanReport(BaseModel):
    """The complete dual-payload scan report (aegis_report.json)."""

    aegis_version: str = __version__
    scan_target: str = ""
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    deterministic: DeterministicPayload = Field(default_factory=DeterministicPayload)
    ephemeral: EphemeralPayload = Field(default_factory=EphemeralPayload)
