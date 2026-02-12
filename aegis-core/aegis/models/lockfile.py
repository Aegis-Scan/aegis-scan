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

"""Pydantic model for the aegis.lock signed lockfile."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from aegis import __version__
from aegis.models.capabilities import CombinationRisk
from aegis.models.report import MerkleTree, RiskScore


class SignatureSlot(BaseModel):
    """A single signature slot (developer or registry)."""

    key_id: str  # "ed25519:base64-of-public-key"
    value: str  # base64-encoded Ed25519 signature
    signed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class Signatures(BaseModel):
    """Extensible signature container with named slots.

    Phase 1: only 'developer' is populated.
    Phase 2: 'registry' is added by the Aegis authority.
    """

    developer: Optional[SignatureSlot] = None
    registry: Optional[SignatureSlot] = None


# The exact fields covered by the signature.
# risk_score.static is signed; llm_adjustment and final are NOT.
SIGNED_FIELDS = [
    "aegis_version",
    "capabilities",
    "cert_id",
    "combination_risks",
    "external_binaries",
    "manifest_source",
    "merkle_tree",
    "path_violations",
    "risk_score.static",
]


class AegisLock(BaseModel):
    """The aegis.lock signed lockfile artifact.

    Keys are sorted alphabetically in canonical JSON output.
    Line endings are LF.
    """

    aegis_version: str = __version__
    capabilities: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    cert_id: str = ""
    combination_risks: list[dict[str, Any]] = Field(default_factory=list)
    external_binaries: list[str] = Field(default_factory=list)
    manifest_source: str = "git"
    merkle_tree: dict[str, Any] = Field(default_factory=dict)
    path_violations: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: dict[str, Any] = Field(
        default_factory=lambda: {"static": 0, "llm_adjustment": 0, "final": 0}
    )
    signatures: dict[str, Any] = Field(
        default_factory=lambda: {"developer": None, "registry": None}
    )
    signed_fields: list[str] = Field(default_factory=lambda: list(SIGNED_FIELDS))

    def get_signable_payload(self) -> str:
        """Serialize only the signed fields to canonical JSON.

        This is the string that gets signed by Ed25519.
        Returns canonical JSON: sorted keys, 2-space indent, LF line endings.
        """
        data: dict[str, Any] = {}
        full_dict = self.model_dump()

        for field_path in self.signed_fields:
            if "." in field_path:
                parts = field_path.split(".")
                # Navigate into nested dict
                value = full_dict
                for part in parts:
                    value = value[part]
                data[field_path] = value
            else:
                data[field_path] = full_dict[field_path]

        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    def to_canonical_json(self) -> str:
        """Serialize to canonical JSON (sorted keys, LF, trailing newline)."""
        return (
            json.dumps(
                self.model_dump(), sort_keys=True, indent=2, ensure_ascii=False
            )
            + "\n"
        )
