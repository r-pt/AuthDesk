"""Tier 1: Feature Coverage - Vault Cryptographic Architecture.

Verifies:
- Two-tier envelope encryption model (KEK wraps 32-byte MK, MK encrypts payload).
- Argon2id KDF parameters (m=64 MiB = 65536 KiB, t=3, p=1, salt >= 16 bytes).
- XChaCha20-Poly1305 AEAD parameters (24-byte random nonce, 16-byte Poly1305 MAC tag).
- Cryptographic Associated Authenticated Data (AAD) binding for anti-tampering.
"""

import base64
import json
import struct
from pathlib import Path
from typing import Type

import pytest

from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.mark.tier(1)
@pytest.mark.milestone("M2")
class TestVaultCryptoStorage:
    """Validates cryptographic vault architecture and parameter compliance."""

    def test_argon2id_parameters_compliance(self, vault_oracle: Type[VaultOracle]):
        """Verifies Argon2id parameters match RFC 9106 and project specifications."""
        assert vault_oracle.EXPECTED_M_COST_KIB == 65536, "Argon2id memory cost must be 64 MiB (65536 KiB)"
        assert vault_oracle.EXPECTED_T_COST == 3, "Argon2id iterations (t) must be 3"
        assert vault_oracle.EXPECTED_P_COST == 1, "Argon2id parallelism (p) must be 1"
        assert vault_oracle.MIN_SALT_BYTES >= 16, "Argon2id salt must be >= 16 bytes"

    def test_xchacha20_poly1305_parameters(self, vault_oracle: Type[VaultOracle]):
        """Verifies symmetric encryption parameters (24-byte extended nonce, 16-byte tag)."""
        assert vault_oracle.NONCE_BYTES == 24, "XChaCha20 requires a 24-byte (192-bit) nonce"
        assert vault_oracle.MK_BYTES == 32, "Master Key must be 32 bytes (256-bit)"
        assert vault_oracle.POLY1305_TAG_BYTES == 16, "Poly1305 MAC tag must be 16 bytes (128-bit)"

    def test_wrapped_master_key_aad_construction(self, vault_oracle: Type[VaultOracle]):
        """Verifies AAD for wrapped Master Key binds version, KDF params, and salt."""
        salt = b"S" * 32
        version = 1
        m_cost = 65536
        t_cost = 3
        p_cost = 1

        aad = vault_oracle.compute_wrapped_key_aad(version, m_cost, t_cost, p_cost, salt)
        assert aad.startswith(b"AUTHDESK_MK_V1:")
        # Check packed parameters
        expected_params = struct.pack(">IIII", version, m_cost, t_cost, p_cost)
        assert expected_params in aad
        assert aad.endswith(salt)
        assert len(aad) == len(b"AUTHDESK_MK_V1:") + 16 + 32

    def test_payload_aad_construction(self, vault_oracle: Type[VaultOracle]):
        """Verifies AAD for payload binds version and updated_at timestamp."""
        version = 1
        updated_at = 1710000000

        aad = vault_oracle.compute_payload_aad(version, updated_at)
        assert aad.startswith(b"AUTHDESK_PAYLOAD_V1:")
        expected_params = struct.pack(">Iq", version, updated_at)
        assert aad.endswith(expected_params)
        assert len(aad) == len(b"AUTHDESK_PAYLOAD_V1:") + 12

    def test_sample_envelope_validation(self, vault_oracle: Type[VaultOracle]):
        """Verifies that an authoritative envelope generated per spec passes full schema validation."""
        valid_envelope = {
            "magic": "AUTHDESK_VAULT",
            "version": 1,
            "created_at": 1710000000,
            "updated_at": 1710000000,
            "kdf": {
                "algorithm": "Argon2id",
                "m_cost_kib": 65536,
                "t_cost": 3,
                "p_cost": 1,
                "salt_b64": base64.b64encode(b"0" * 32).decode(),
            },
            "wrapped_master_key": {
                "nonce_b64": base64.b64encode(b"N" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"C" * 48).decode(),  # 32B MK + 16B tag
            },
            "payload": {
                "nonce_b64": base64.b64encode(b"P" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"E" * 64).decode(),
            },
        }

        is_valid, errors = vault_oracle.validate_envelope_structure(valid_envelope)
        assert is_valid, f"Sample envelope failed validation: {errors}"
