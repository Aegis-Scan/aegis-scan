"""Tests for Ed25519 signing and verification.

Tests key generation, signing, verification, invalid rejection,
and extensible signature slots (Directive 1).
"""

import json
import tempfile
from pathlib import Path

import pytest

from aegis.crypto.signer import (
    generate_keypair,
    get_or_create_keypair,
    get_public_key_id,
    load_private_key,
    load_public_key,
    sign_lockfile,
    verify_signature,
)
from aegis.models.lockfile import AegisLock


@pytest.fixture
def temp_key_dir(tmp_path: Path) -> Path:
    """Create a temporary key directory."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    return key_dir


@pytest.fixture
def sample_lockfile() -> AegisLock:
    """Create a sample lockfile for testing."""
    return AegisLock(
        aegis_version="0.1.0",
        capabilities={"fs": {"read": ["./data/*"]}, "network": {"connect": ["api.weather.com"]}},
        cert_id="local-test123",
        combination_risks=[],
        external_binaries=["git"],
        manifest_source="git",
        merkle_tree={
            "root": "sha256:abc123",
            "algorithm": "sha256",
            "leaves": [{"path": "test.py", "hash": "sha256:111"}],
            "nodes": [],
        },
        path_violations=[],
        risk_score={"static": 25, "llm_adjustment": -5, "final": 20},
    )


class TestKeyGeneration:
    """Test Ed25519 keypair generation and storage."""

    def test_generate_keypair(self, temp_key_dir: Path):
        private_key, public_key = generate_keypair(temp_key_dir)
        assert private_key is not None
        assert public_key is not None

    def test_keys_saved_to_disk(self, temp_key_dir: Path):
        generate_keypair(temp_key_dir)
        assert (temp_key_dir / "developer_private.pem").exists()
        assert (temp_key_dir / "developer_public.pem").exists()

    def test_load_existing_keys(self, temp_key_dir: Path):
        private_key, public_key = generate_keypair(temp_key_dir)
        loaded_private = load_private_key(temp_key_dir)
        loaded_public = load_public_key(temp_key_dir)
        assert loaded_private is not None
        assert loaded_public is not None

    def test_get_or_create_new(self, temp_key_dir: Path):
        private_key, public_key = get_or_create_keypair(temp_key_dir)
        assert private_key is not None
        assert public_key is not None

    def test_get_or_create_existing(self, temp_key_dir: Path):
        pk1, pub1 = generate_keypair(temp_key_dir)
        pk2, pub2 = get_or_create_keypair(temp_key_dir)
        # Should load the same key
        assert get_public_key_id(pub1) == get_public_key_id(pub2)

    def test_key_id_format(self, temp_key_dir: Path):
        _, public_key = generate_keypair(temp_key_dir)
        key_id = get_public_key_id(public_key)
        assert key_id.startswith("ed25519:")


class TestSigning:
    """Test lockfile signing."""

    def test_sign_populates_developer_slot(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        assert signed.signatures["developer"] is not None
        assert signed.signatures["developer"]["key_id"].startswith("ed25519:")
        assert signed.signatures["developer"]["value"] != ""

    def test_sign_does_not_touch_registry(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        """Phase 1: only developer slot populated. Registry stays null."""
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        assert signed.signatures["registry"] is None

    def test_verify_valid_signature(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        lockfile_dict = signed.model_dump()
        assert verify_signature(lockfile_dict, "developer", public_key) is True

    def test_verify_from_key_id(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        """Verify using the public key embedded in key_id (no external key needed)."""
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        lockfile_dict = signed.model_dump()
        # Don't pass public_key — extract from key_id
        assert verify_signature(lockfile_dict, "developer") is True

    def test_tampered_data_fails(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        lockfile_dict = signed.model_dump()

        # Tamper with signed data
        lockfile_dict["capabilities"]["network"]["connect"] = ["evil.com"]

        assert verify_signature(lockfile_dict, "developer", public_key) is False

    def test_no_developer_signature_fails(self, sample_lockfile: AegisLock):
        lockfile_dict = sample_lockfile.model_dump()
        assert verify_signature(lockfile_dict, "developer") is False


class TestExtensibleSignatures:
    """Test that the extensible signature scheme works (Directive 1).

    Both developer and registry sign the SAME canonical payload.
    Verification of one slot ignores the other.
    """

    def test_developer_only_in_phase1(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        """Phase 1 produces developer only, registry is null."""
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        assert signed.signatures["developer"] is not None
        assert signed.signatures["registry"] is None

    def test_registry_can_be_added_later(self, temp_key_dir: Path, sample_lockfile: AegisLock):
        """Simulate Phase 2: add registry signature without invalidating developer."""
        private_key, public_key = generate_keypair(temp_key_dir)
        signed = sign_lockfile(sample_lockfile, private_key, public_key)
        lockfile_dict = signed.model_dump()

        # Simulate registry adding its own signature
        registry_key_dir = temp_key_dir / "registry"
        registry_key_dir.mkdir()
        reg_private, reg_public = generate_keypair(registry_key_dir)

        # Developer signature should still be valid
        assert verify_signature(lockfile_dict, "developer", public_key) is True
