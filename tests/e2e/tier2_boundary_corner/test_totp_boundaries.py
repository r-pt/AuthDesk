"""Tier 2: Boundary & Corner Cases - TOTP Engine.

Verifies:
- Empty secrets (whitespace only, empty string).
- Invalid Base32 characters ('8', '9', punctuation, unicode emojis).
- Extreme periods (step=0 division by zero prevention, step=1, step=300, step=3600).
- Epoch boundaries (T=0, negative timestamps, Year 2038 / 20000000000, 64-bit timestamps).
- Invalid digit counts (digits=5, 7, 9, 0 must be rejected).
"""

from typing import Type
import pytest

from tests.e2e.oracle.totp_oracle import TotpOracle


@pytest.mark.tier(2)
@pytest.mark.milestone("M1")
class TestTotpBoundaries:
    """Validates boundary conditions, extreme inputs, and error handling for the TOTP engine."""

    def test_empty_secret_rejection(self, totp_oracle: Type[TotpOracle]):
        """Verifies empty or whitespace-only secrets are rejected with clean error."""
        empty_inputs = ["", "   ", "\t\n", "   -   "]
        for inp in empty_inputs:
            with pytest.raises(ValueError, match="empty"):
                totp_oracle.sanitize_base32(inp)

    def test_invalid_base32_characters(self, totp_oracle: Type[TotpOracle]):
        """Verifies strings with non-base32 characters ('8', '9', symbols, emojis) are rejected."""
        invalid_inputs = [
            "JBSWY3DPEHPK3PX8",  # '8' is invalid in RFC 4648 Base32
            "JBSWY3DPEHPK3PX9",  # '9' is invalid
            "JBSWY3DP!@#$%",     # symbols
            "JBSWY🔑HPK3PXP",     # emoji
            "JBSWY3DP0189",      # 0, 1, 8, 9 are all invalid in standard Base32
        ]
        for inp in invalid_inputs:
            with pytest.raises(ValueError, match="Invalid Base32"):
                totp_oracle.sanitize_base32(inp)

    def test_extreme_period_step_zero(self, totp_oracle: Type[TotpOracle]):
        """Verifies step=0 is cleanly rejected and prevents division-by-zero panics."""
        secret = "JBSWY3DPEHPK3PXP"
        with pytest.raises(ValueError, match="positive"):
            totp_oracle.generate_totp(secret, timestamp=1000, step=0)

    def test_extreme_period_boundaries(self, totp_oracle: Type[TotpOracle]):
        """Verifies calculation with boundary steps: step=1, step=300, step=3600."""
        secret = "JBSWY3DPEHPK3PXP"
        ts = 1234567890

        # step=1: changes every second
        c_step1_a = totp_oracle.generate_totp(secret, timestamp=ts, step=1)
        c_step1_b = totp_oracle.generate_totp(secret, timestamp=ts + 1, step=1)
        assert len(c_step1_a) == 6
        assert len(c_step1_b) == 6
        assert c_step1_a != c_step1_b

        # step=300 (5 minutes)
        c_step300 = totp_oracle.generate_totp(secret, timestamp=ts, step=300)
        assert len(c_step300) == 6

        # step=3600 (1 hour)
        c_step3600 = totp_oracle.generate_totp(secret, timestamp=ts, step=3600)
        assert len(c_step3600) == 6

    def test_epoch_boundary_zero(self, totp_oracle: Type[TotpOracle]):
        """Verifies timestamp T=0 (Unix epoch start) computes valid TOTP code without panic."""
        secret = "JBSWY3DPEHPK3PXP"
        code = totp_oracle.generate_totp(secret, timestamp=0, step=30)
        assert len(code) == 6
        assert code.isdigit()

    def test_negative_timestamp_rejection(self, totp_oracle: Type[TotpOracle]):
        """Verifies negative timestamps (pre-epoch) are rejected."""
        secret = "JBSWY3DPEHPK3PXP"
        with pytest.raises(ValueError, match="non-negative"):
            totp_oracle.generate_totp(secret, timestamp=-1, step=30)

    def test_large_epoch_timestamp_year_2038_and_beyond(self, totp_oracle: Type[TotpOracle]):
        """Verifies timestamps beyond 32-bit signed integer boundary (Year 2038 / 20000000000)."""
        secret = totp_oracle.RFC_TEST_SECRETS["SHA1"]

        # T = 2000000000 (Year 2033)
        c_2033 = totp_oracle.generate_totp(secret, timestamp=2000000000, step=30, digits=8, algorithm="SHA1")
        assert c_2033 == "69279037"

        # T = 20000000000 (Year 2603, well beyond 32-bit limit)
        c_2603 = totp_oracle.generate_totp(secret, timestamp=20000000000, step=30, digits=8, algorithm="SHA1")
        assert c_2603 == "65353130"

    def test_invalid_digit_lengths(self, totp_oracle: Type[TotpOracle]):
        """Verifies non-standard digit counts (5, 7, 9, 0) are rejected."""
        secret = "JBSWY3DPEHPK3PXP"
        for invalid_digits in [0, 1, 4, 5, 7, 9, 10]:
            with pytest.raises(ValueError, match="Digits must be 6 or 8"):
                totp_oracle.generate_totp(secret, timestamp=1000, step=30, digits=invalid_digits)
