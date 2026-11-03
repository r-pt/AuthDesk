"""RFC 6238 and RFC 4226 Reference Implementation Oracle.

Authoritative source for TOTP and HOTP computations, dynamic truncation,
Base32 sanitization, and Appendix B test vector validation.
"""

import base64
import hashlib
import hmac
import math
import struct
from typing import Optional, Tuple


class TotpOracle:
    """RFC 6238 authoritative TOTP oracle."""

    SUPPORTED_ALGORITHMS = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }

    # RFC 6238 Appendix B reference test secrets
    RFC_TEST_SECRETS = {
        "SHA1": b"12345678901234567890",  # 20 bytes
        "SHA256": b"12345678901234567890123456789012",  # 32 bytes
        "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",  # 64 bytes
    }

    # RFC 6238 Appendix B test vectors: (timestamp, counter_hex, sha1_8, sha256_8, sha512_8)
    RFC_APPENDIX_B_VECTORS = [
        (59, "0000000000000001", "94287082", "46119246", "90693936"),
        (1111111109, "00000000023523EC", "07081804", "68084774", "25091201"),
        (1111111111, "00000000023523ED", "14050471", "67062674", "99943326"),
        (1234567890, "000000000273EF07", "89005924", "91819424", "93441116"),
        (2000000000, "0000000003F3E0A2", "69279037", "90698825", "38618901"),
        (20000000000, "000000002782A0E2", "65353130", "77737706", "47863826"),
    ]

    @staticmethod
    def sanitize_base32(secret: str) -> bytes:
        """Sanitizes Base32 input string and decodes to raw bytes.

        Removes spaces and hyphens, converts to uppercase, strips prior padding,
        validates RFC 4648 alphabet, and re-pads with '=' as needed.
        Raises ValueError if secret is empty or contains non-base32 characters.
        """
        if not secret or not secret.strip():
            raise ValueError("Secret cannot be empty")

        cleaned = secret.replace(" ", "").replace("-", "").upper()
        unpadded = cleaned.rstrip("=")
        if not unpadded:
            raise ValueError("Secret cannot be empty")

        # Validate Base32 character set (A-Z, 2-7)
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        if not set(unpadded).issubset(valid_chars):
            raise ValueError(f"Invalid Base32 character detected in '{secret}'")

        # Re-pad to multiple of 8
        missing_padding = len(unpadded) % 8
        if missing_padding:
            unpadded += "=" * (8 - missing_padding)

        try:
            return base64.b32decode(unpadded)
        except Exception as e:
            raise ValueError(f"Base32 decoding failed: {e}") from e

    @classmethod
    def generate_hotp(
        cls,
        secret_bytes: bytes,
        counter: int,
        digits: int = 6,
        algorithm: str = "SHA1",
    ) -> str:
        """Computes RFC 4226 HOTP for given secret and counter."""
        if digits not in (6, 8):
            raise ValueError(f"Digits must be 6 or 8, got {digits}")

        algo_norm = algorithm.upper().replace("-", "")
        if algo_norm not in cls.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Must be SHA1, SHA256, or SHA512.")

        hash_func = cls.SUPPORTED_ALGORITHMS[algo_norm]

        # Counter packed as 8-byte big-endian unsigned integer
        counter_bytes = struct.pack(">Q", counter)

        # Compute HMAC
        h = hmac.new(secret_bytes, counter_bytes, hash_func).digest()

        # Dynamic truncation (RFC 4226 Section 5.4)
        offset = h[-1] & 0x0F
        binary_code = (
            ((h[offset] & 0x7F) << 24)
            | ((h[offset + 1] & 0xFF) << 16)
            | ((h[offset + 2] & 0xFF) << 8)
            | (h[offset + 3] & 0xFF)
        )

        mod = 10**digits
        code = binary_code % mod
        return f"{code:0{digits}d}"

    @classmethod
    def generate_totp(
        cls,
        secret: bytes | str,
        timestamp: int,
        step: int = 30,
        t0: int = 0,
        digits: int = 6,
        algorithm: str = "SHA1",
    ) -> str:
        """Computes RFC 6238 TOTP."""
        if step <= 0:
            raise ValueError(f"Time step must be positive, got {step}")
        if timestamp < 0:
            raise ValueError(f"Timestamp must be non-negative, got {timestamp}")

        if isinstance(secret, str):
            secret_bytes = cls.sanitize_base32(secret)
        else:
            secret_bytes = secret

        counter = (timestamp - t0) // step
        return cls.generate_hotp(secret_bytes, counter, digits=digits, algorithm=algorithm)

    @classmethod
    def calculate_countdown(cls, timestamp: int, step: int = 30, t0: int = 0) -> Tuple[int, float]:
        """Calculates remaining seconds and progress ratio in current time step.

        Returns (remaining_seconds, progress_ratio).
        """
        if step <= 0:
            raise ValueError("Step must be > 0")

        elapsed = (timestamp - t0) % step
        remaining = step - elapsed
        if remaining == 0:
            remaining = step
        ratio = round(remaining / step, 4)
        return remaining, ratio
