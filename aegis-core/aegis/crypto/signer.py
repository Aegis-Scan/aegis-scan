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

"""Ed25519 local keypair management and signing.

Manages developer keys stored in ~/.aegis/keys/.
Signs the canonical JSON of signed fields.
Supports extensible signature slots (developer + registry).
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from aegis.models.lockfile import AegisLock, SignatureSlot

logger = logging.getLogger(__name__)

# Default key storage directory
DEFAULT_KEY_DIR = Path.home() / ".aegis" / "keys"


def get_key_dir() -> Path:
    """Get the key storage directory, creating it if needed."""
    key_dir = DEFAULT_KEY_DIR
    key_dir.mkdir(parents=True, exist_ok=True)
    return key_dir


def generate_keypair(key_dir: Path | None = None) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair and save to disk.

    Args:
        key_dir: Directory to store keys (default: ~/.aegis/keys/)

    Returns:
        (private_key, public_key) tuple
    """
    if key_dir is None:
        key_dir = get_key_dir()

    key_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    private_path = key_dir / "developer_private.pem"
    private_path.write_bytes(private_pem)

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = key_dir / "developer_public.pem"
    public_path.write_bytes(public_pem)

    logger.info("Generated new Ed25519 keypair in %s", key_dir)
    return private_key, public_key


def load_private_key(key_dir: Path | None = None) -> Ed25519PrivateKey | None:
    """Load existing private key from disk."""
    if key_dir is None:
        key_dir = get_key_dir()

    private_path = key_dir / "developer_private.pem"
    if not private_path.exists():
        return None

    private_pem = private_path.read_bytes()
    key = load_pem_private_key(private_pem, password=None)
    if isinstance(key, Ed25519PrivateKey):
        return key
    return None


def load_public_key(key_dir: Path | None = None) -> Ed25519PublicKey | None:
    """Load existing public key from disk."""
    if key_dir is None:
        key_dir = get_key_dir()

    public_path = key_dir / "developer_public.pem"
    if not public_path.exists():
        return None

    public_pem = public_path.read_bytes()
    key = load_pem_public_key(public_pem)
    if isinstance(key, Ed25519PublicKey):
        return key
    return None


def get_or_create_keypair(
    key_dir: Path | None = None,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load existing keypair or generate a new one.

    Returns:
        (private_key, public_key) tuple
    """
    if key_dir is None:
        key_dir = get_key_dir()

    private_key = load_private_key(key_dir)
    if private_key is not None:
        public_key = private_key.public_key()
        logger.debug("Loaded existing keypair from %s", key_dir)
        return private_key, public_key

    return generate_keypair(key_dir)


def get_public_key_id(public_key: Ed25519PublicKey) -> str:
    """Get the key ID string for a public key.

    Format: 'ed25519:base64-of-raw-public-key'
    """
    raw_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    return f"ed25519:{b64}"


def sign_lockfile(
    lockfile: AegisLock,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
) -> AegisLock:
    """Sign the lockfile with the developer's private key.

    Populates signatures.developer slot. Does NOT touch signatures.registry.

    Args:
        lockfile: The lockfile to sign.
        private_key: Developer's Ed25519 private key.
        public_key: Developer's Ed25519 public key (for key_id).

    Returns:
        The lockfile with signatures.developer populated.
    """
    # Get the canonical payload to sign
    payload = lockfile.get_signable_payload()
    payload_bytes = payload.encode("utf-8")

    # Sign with Ed25519
    signature_bytes = private_key.sign(payload_bytes)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Build the signature slot
    key_id = get_public_key_id(public_key)
    signed_at = datetime.now(timezone.utc).isoformat()

    lockfile.signatures["developer"] = {
        "key_id": key_id,
        "value": signature_b64,
        "signed_at": signed_at,
    }

    return lockfile


def verify_signature(
    lockfile_data: dict,
    slot_name: str = "developer",
    public_key: Ed25519PublicKey | None = None,
) -> bool:
    """Verify a signature slot in a lockfile.

    Args:
        lockfile_data: Parsed lockfile dict.
        slot_name: "developer" or "registry".
        public_key: Optional public key to verify against.
                    If None, extracts from signature's key_id.

    Returns:
        True if signature is valid.
    """
    signatures = lockfile_data.get("signatures", {})
    slot = signatures.get(slot_name)

    if not slot:
        logger.error("No %s signature in lockfile", slot_name)
        return False

    key_id = slot["key_id"]
    sig_b64 = slot["value"]

    # Extract or use provided public key
    if public_key is None:
        # Parse key_id to get public key bytes
        if not key_id.startswith("ed25519:"):
            logger.error("Unknown key type in key_id: %s", key_id)
            return False

        pub_bytes = base64.b64decode(key_id.removeprefix("ed25519:"))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as Ed25519Pub,
        )

        public_key = Ed25519Pub.from_public_bytes(pub_bytes)

    # Reconstruct signable payload
    signed_fields = lockfile_data.get("signed_fields", [])
    payload_data = {}

    for field_path in signed_fields:
        if "." in field_path:
            parts = field_path.split(".")
            value = lockfile_data
            for part in parts:
                value = value[part]
            payload_data[field_path] = value
        else:
            payload_data[field_path] = lockfile_data[field_path]

    payload = json.dumps(payload_data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    payload_bytes = payload.encode("utf-8")

    # Verify
    sig_bytes = base64.b64decode(sig_b64)
    try:
        public_key.verify(sig_bytes, payload_bytes)
        return True
    except Exception as e:
        logger.error("Signature verification failed: %s", e)
        return False
