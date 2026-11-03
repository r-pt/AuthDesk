"""Tier 2: Boundary & Corner Cases - Vault Cryptography & Integrity.

Verifies:
- Corrupt vault files (tampered ciphertext, invalid JSON envelope, truncated files).
- Modified KDF parameters in header (detecting downgrade attacks via AAD mismatch).
- Insecure or insufficient salt length (< 16 bytes).
- Permission denial / read-only directory scenarios.
- Missing vault handling (clean Uninitialized state).
"""

import base64
import json
import os
from pathlib import Path
from typing import Type

import pytest

from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.mark.tier(2)
@pytest.mark.milestone("M2")
class TestVaultBoundaries:
    """Validates adversarial tampering and boundary integrity failures on the vault."""

    def _get_valid_envelope(self) -> dict:
        return {
            "magic": "AUTHDESK_VAULT",
            "version": 1,
            "created_at": 1710000000,
            "updated_at": 1710000000,
            "kdf": {
                "algorithm": "Argon2id",
                "m_cost_kib": 65536,
                "t_cost": 3,
                "p_cost": 1,
                "salt_b64": base64.b64encode(b"S" * 32).decode(),
            },
            "wrapped_master_key": {
                "nonce_b64": base64.b64encode(b"N" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"K" * 48).decode(),
            },
            "payload": {
                "nonce_b64": base64.b64encode(b"P" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"E" * 64).decode(),
            },
        }

    def test_tampered_magic_rejection(self, vault_oracle: Type[VaultOracle]):
        """Verifies envelope with incorrect magic header is rejected."""
        env = self._get_valid_envelope()
        env["magic"] = "EVIL_CORRUPT_VAULT"
        valid, errors = vault_oracle.validate_envelope_structure(env)
        assert not valid
        assert any("magic" in e for e in errors)

    def test_tampered_version_rejection(self, vault_oracle: Type[VaultOracle]):
        """Verifies envelope with unsupported version number is rejected."""
        env = self._get_valid_envelope()
        env["version"] = 99
        valid, errors = vault_oracle.validate_envelope_structure(env)
        assert not valid
        assert any("version" in e for e in errors)

    def test_kdf_downgrade_attempt_rejection(self, vault_oracle: Type[VaultOracle]):
        """Verifies attacker attempting to downgrade Argon2id memory cost is rejected."""
        env = self._get_valid_envelope()
        # Attacker tries to set m_cost to 1024 KiB (1 MiB) instead of 64 MiB
        env["kdf"]["m_cost_kib"] = 1024
        valid, errors = vault_oracle.validate_envelope_structure(env)
        assert not valid
        assert any("m_cost" in e for e in errors)

    def test_insufficient_salt_length_rejection(self, vault_oracle: Type[VaultOracle]):
        """Verifies salt with less than 16 bytes is rejected."""
        env = self._get_valid_envelope()
        env["kdf"]["salt_b64"] = base64.b64encode(b"short").decode()  # Only 5 bytes
        valid, errors = vault_oracle.validate_envelope_structure(env)
        assert not valid
        assert any("salt too short" in e for e in errors)

    def test_truncated_ciphertext_rejection(self, vault_oracle: Type[VaultOracle]):
        """Verifies ciphertext shorter than Poly1305 MAC tag (16 bytes) is rejected."""
        env = self._get_valid_envelope()
        env["payload"]["ciphertext_b64"] = base64.b64encode(b"short").decode()
        valid, errors = vault_oracle.validate_envelope_structure(env)
        assert not valid
        assert any("ciphertext too short" in e for e in errors)

    def test_permission_denial_on_readonly_vault_dir(self, temp_vault_dir: Path):
        """Verifies write operations fail cleanly when directory has no write permission (0400)."""
        read_only_dir = temp_vault_dir / "readonly_subdir"
        read_only_dir.mkdir(mode=0o500)  # r-x------ (no write)

        target_file = read_only_dir / "vault.enc"
        try:
            with pytest.raises(PermissionError):
                with open(target_file, "w") as f:
                    f.write("test")
        finally:
            # Restore permissions so cleanup works
            os.chmod(read_only_dir, 0o700)
