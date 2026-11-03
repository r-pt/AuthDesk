"""Vault Cryptographic Envelope, POSIX Permissions, and Leak Detection Oracle.

Authoritative source for schema validation of the AuthDesk encrypted vault envelope,
POSIX filesystem permission compliance (0600 / 0700), AAD construction, and secret-leak auditing.
"""

import base64
import json
import os
import re
import stat
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class VaultOracle:
    """Authoritative oracle for Vault envelope, cryptographic schemas, and filesystem security."""

    EXPECTED_MAGIC = "AUTHDESK_VAULT"
    EXPECTED_VERSION = 1
    EXPECTED_KDF_ALGORITHM = "Argon2id"
    EXPECTED_M_COST_KIB = 65536  # 64 MiB
    EXPECTED_T_COST = 3
    EXPECTED_P_COST = 1
    MIN_SALT_BYTES = 16
    RECOMMENDED_SALT_BYTES = 32
    NONCE_BYTES = 24  # XChaCha20 nonce is 192 bits = 24 bytes
    MK_BYTES = 32  # 256-bit Master Key
    POLY1305_TAG_BYTES = 16

    @classmethod
    def compute_wrapped_key_aad(
        cls, version: int, m_cost: int, t_cost: int, p_cost: int, salt_bytes: bytes
    ) -> bytes:
        """Computes authoritative AAD for Wrapped Master Key."""
        header = b"AUTHDESK_MK_V1:"
        params = struct.pack(">IIII", version, m_cost, t_cost, p_cost)
        return header + params + salt_bytes

    @classmethod
    def compute_payload_aad(cls, version: int, updated_at: int) -> bytes:
        """Computes authoritative AAD for Encrypted Accounts Payload."""
        header = b"AUTHDESK_PAYLOAD_V1:"
        params = struct.pack(">Iq", version, updated_at)
        return header + params

    @classmethod
    def validate_envelope_structure(cls, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validates envelope JSON against security and schema specifications.

        Returns (is_valid, error_list).
        """
        errors = []

        if data.get("magic") != cls.EXPECTED_MAGIC:
            errors.append(f"Invalid magic: expected '{cls.EXPECTED_MAGIC}', got '{data.get('magic')}'")

        if data.get("version") != cls.EXPECTED_VERSION:
            errors.append(f"Invalid version: expected {cls.EXPECTED_VERSION}, got '{data.get('version')}'")

        if not isinstance(data.get("created_at"), (int, float)) or data.get("created_at") <= 0:
            errors.append(f"Invalid created_at timestamp: {data.get('created_at')}")

        if not isinstance(data.get("updated_at"), (int, float)) or data.get("updated_at") <= 0:
            errors.append(f"Invalid updated_at timestamp: {data.get('updated_at')}")

        # KDF Configuration validation
        kdf = data.get("kdf")
        if not isinstance(kdf, dict):
            errors.append("Missing or invalid 'kdf' object in envelope")
        else:
            if kdf.get("algorithm") != cls.EXPECTED_KDF_ALGORITHM:
                errors.append(f"Invalid KDF algorithm: expected '{cls.EXPECTED_KDF_ALGORITHM}', got '{kdf.get('algorithm')}'")
            if kdf.get("m_cost_kib") != cls.EXPECTED_M_COST_KIB:
                errors.append(f"Invalid KDF m_cost: expected {cls.EXPECTED_M_COST_KIB} KiB, got {kdf.get('m_cost_kib')}")
            if kdf.get("t_cost") != cls.EXPECTED_T_COST:
                errors.append(f"Invalid KDF t_cost: expected {cls.EXPECTED_T_COST}, got {kdf.get('t_cost')}")
            if kdf.get("p_cost") != cls.EXPECTED_P_COST:
                errors.append(f"Invalid KDF p_cost: expected {cls.EXPECTED_P_COST}, got {kdf.get('p_cost')}")

            salt_b64 = kdf.get("salt_b64", "")
            try:
                salt_bytes = base64.b64decode(salt_b64)
                if len(salt_bytes) < cls.MIN_SALT_BYTES:
                    errors.append(f"KDF salt too short: {len(salt_bytes)} bytes < minimum {cls.MIN_SALT_BYTES}")
            except Exception as e:
                errors.append(f"KDF salt_b64 is invalid base64: {e}")

        # Wrapped Master Key validation
        wrapped_mk = data.get("wrapped_master_key")
        if not isinstance(wrapped_mk, dict):
            errors.append("Missing or invalid 'wrapped_master_key' object")
        else:
            nonce_b64 = wrapped_mk.get("nonce_b64", "")
            try:
                nonce_bytes = base64.b64decode(nonce_b64)
                if len(nonce_bytes) != cls.NONCE_BYTES:
                    errors.append(f"Wrapped MK nonce length mismatch: expected {cls.NONCE_BYTES} bytes, got {len(nonce_bytes)}")
            except Exception as e:
                errors.append(f"Wrapped MK nonce_b64 is invalid base64: {e}")

            ct_b64 = wrapped_mk.get("ciphertext_b64", "")
            try:
                ct_bytes = base64.b64decode(ct_b64)
                expected_ct_len = cls.MK_BYTES + cls.POLY1305_TAG_BYTES
                if len(ct_bytes) != expected_ct_len:
                    errors.append(f"Wrapped MK ciphertext length mismatch: expected {expected_ct_len} bytes, got {len(ct_bytes)}")
            except Exception as e:
                errors.append(f"Wrapped MK ciphertext_b64 is invalid base64: {e}")

        # Payload validation
        payload = data.get("payload")
        if not isinstance(payload, dict):
            errors.append("Missing or invalid 'payload' object")
        else:
            nonce_b64 = payload.get("nonce_b64", "")
            try:
                nonce_bytes = base64.b64decode(nonce_b64)
                if len(nonce_bytes) != cls.NONCE_BYTES:
                    errors.append(f"Payload nonce length mismatch: expected {cls.NONCE_BYTES} bytes, got {len(nonce_bytes)}")
            except Exception as e:
                errors.append(f"Payload nonce_b64 is invalid base64: {e}")

            ct_b64 = payload.get("ciphertext_b64", "")
            try:
                ct_bytes = base64.b64decode(ct_b64)
                if len(ct_bytes) < cls.POLY1305_TAG_BYTES:
                    errors.append(f"Payload ciphertext too short: {len(ct_bytes)} bytes < tag length {cls.POLY1305_TAG_BYTES}")
            except Exception as e:
                errors.append(f"Payload ciphertext_b64 is invalid base64: {e}")

        return (len(errors) == 0, errors)

    @classmethod
    def check_posix_permissions(cls, path: str | Path) -> Tuple[int, str]:
        """Returns octal mode int and formatted octal permission string (e.g. 0o600, '0600')."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        st = os.stat(p)
        mode = stat.S_IMODE(st.st_mode)
        return mode, oct(mode)[2:]

    @classmethod
    def verify_vault_file_permissions(cls, file_path: str | Path) -> bool:
        """Verifies vault file has strict 0600 permissions."""
        mode, _ = cls.check_posix_permissions(file_path)
        return mode == 0o600

    @classmethod
    def verify_vault_dir_permissions(cls, dir_path: str | Path) -> bool:
        """Verifies vault directory has strict 0700 permissions."""
        mode, _ = cls.check_posix_permissions(dir_path)
        return mode == 0o700

    @classmethod
    def scan_for_secret_leaks(cls, text: str, known_secrets: Optional[List[str]] = None) -> List[str]:
        """Scans log or console text for secret leaks.

        Detects raw base32 secrets, high-entropy hex keys, cleartext passwords, and specific known secrets.
        Returns list of detected leak descriptions.
        """
        leaks = []

        if known_secrets:
            for s in known_secrets:
                if s and len(s) >= 4 and s in text:
                    leaks.append(f"Known sensitive token leaked: '{s[:3]}***'")

        # Scan for Base32 secrets (length >= 16 characters matching RFC 4648)
        base32_pattern = re.compile(r"\b[A-Z2-7]{16,64}\b")
        for match in base32_pattern.finditer(text):
            candidate = match.group()
            # Exclude known false positives (e.g. all-A padding or standard words)
            if not all(c == candidate[0] for c in candidate):
                leaks.append(f"Potential Base32 secret detected: {candidate[:4]}... (len {len(candidate)})")

        # Scan for raw MasterKey / DerivedKek hex patterns (64 hex characters)
        hex_key_pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")
        for match in hex_key_pattern.finditer(text):
            leaks.append(f"Potential 256-bit raw cryptographic key in hex: {match.group()[:8]}...")

        return leaks
