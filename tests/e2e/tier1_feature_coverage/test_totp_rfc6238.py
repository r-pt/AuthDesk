"""Tier 1: Feature Coverage - RFC 6238 TOTP Engine.

Verifies:
- Full RFC 6238 algorithm support: SHA1, SHA256, SHA512.
- 6-digit and 8-digit lengths.
- Leading zero formatting (preserves '005924').
- Configurable time steps (15s, 30s, 60s).
- All RFC 6238 Appendix B test vectors against authoritative oracle.
- Base32 input normalization (whitespace, hyphens, case insensitivity, padding).
"""

from typing import Type
import pytest

from tests.e2e.oracle.totp_oracle import TotpOracle


@pytest.mark.tier(1)
@pytest.mark.milestone("M1")
class TestTotpRfc6238:
    """Validates RFC 6238 TOTP compliance."""

    def test_rfc6238_appendix_b_8_digit_vectors(self, totp_oracle: Type[TotpOracle]):
        """Verifies all 8-digit RFC 6238 Appendix B test vectors across SHA1, SHA256, and SHA512."""
        for ts, counter_hex, exp_sha1, exp_sha256, exp_sha512 in totp_oracle.RFC_APPENDIX_B_VECTORS:
            code_sha1 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA1"], ts, step=30, digits=8, algorithm="SHA1"
            )
            code_sha256 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA256"], ts, step=30, digits=8, algorithm="SHA256"
            )
            code_sha512 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA512"], ts, step=30, digits=8, algorithm="SHA512"
            )

            assert code_sha1 == exp_sha1, f"SHA1 8-digit mismatch at T={ts}: got {code_sha1}, expected {exp_sha1}"
            assert code_sha256 == exp_sha256, f"SHA256 8-digit mismatch at T={ts}: got {code_sha256}, expected {exp_sha256}"
            assert code_sha512 == exp_sha512, f"SHA512 8-digit mismatch at T={ts}: got {code_sha512}, expected {exp_sha512}"

    def test_rfc6238_6_digit_vectors(self, totp_oracle: Type[TotpOracle]):
        """Verifies 6-digit RFC 6238 test vectors, including critical leading double-zero."""
        # Standard derived 6-digit test vectors (mod 10^6)
        vectors_6d = [
            (59, "287082", "119246", "693936"),
            (1111111109, "081804", "084774", "091201"),
            (1111111111, "050471", "062674", "943326"),
            (1234567890, "005924", "819424", "441116"),  # Double zero edge case
            (2000000000, "279037", "698825", "618901"),
            (20000000000, "353130", "737706", "863826"),
        ]

        for ts, exp_sha1, exp_sha256, exp_sha512 in vectors_6d:
            c1 = totp_oracle.generate_totp(totp_oracle.RFC_TEST_SECRETS["SHA1"], ts, step=30, digits=6, algorithm="SHA1")
            c2 = totp_oracle.generate_totp(totp_oracle.RFC_TEST_SECRETS["SHA256"], ts, step=30, digits=6, algorithm="SHA256")
            c3 = totp_oracle.generate_totp(totp_oracle.RFC_TEST_SECRETS["SHA512"], ts, step=30, digits=6, algorithm="SHA512")

            assert c1 == exp_sha1, f"SHA1 6-digit mismatch at T={ts}: got {c1}, expected {exp_sha1}"
            assert c2 == exp_sha256, f"SHA256 6-digit mismatch at T={ts}: got {c2}, expected {exp_sha256}"
            assert c3 == exp_sha512, f"SHA512 6-digit mismatch at T={ts}: got {c3}, expected {exp_sha512}"

    def test_totp_leading_zero_formatting(self, totp_oracle: Type[TotpOracle]):
        """Verifies that integer values with leading zeroes are formatted with exact length."""
        # At T=1234567890, SHA1 code is 005924 (starts with "00")
        code = totp_oracle.generate_totp(
            totp_oracle.RFC_TEST_SECRETS["SHA1"], 1234567890, step=30, digits=6, algorithm="SHA1"
        )
        assert len(code) == 6, f"Code length must be exactly 6, got {len(code)}"
        assert code.startswith("00"), f"Code must preserve leading zeroes, got {code}"
        assert code == "005924"

    def test_configurable_time_steps(self, totp_oracle: Type[TotpOracle]):
        """Verifies TOTP calculation across various time steps: 15s, 30s, 60s."""
        secret = "JBSWY3DPEHPK3PXP"  # "Hello!\xde\xad\xbe\xef" in Base32
        ts = 1000

        code_15s = totp_oracle.generate_totp(secret, ts, step=15, digits=6)
        code_30s = totp_oracle.generate_totp(secret, ts, step=30, digits=6)
        code_60s = totp_oracle.generate_totp(secret, ts, step=60, digits=6)

        assert len(code_15s) == 6 and code_15s.isdigit()
        assert len(code_30s) == 6 and code_30s.isdigit()
        assert len(code_60s) == 6 and code_60s.isdigit()
        # Different time steps should generally produce different codes
        assert code_15s != code_30s or code_30s != code_60s

    def test_countdown_and_progress_ratio(self, totp_oracle: Type[TotpOracle]):
        """Verifies remaining seconds and progress ratio calculations."""
        step = 30
        # Exactly at start of interval
        rem, ratio = totp_oracle.calculate_countdown(timestamp=300, step=step)
        assert rem == 30
        assert ratio == 1.0

        # Halfway through interval
        rem, ratio = totp_oracle.calculate_countdown(timestamp=315, step=step)
        assert rem == 15
        assert ratio == 0.5

        # Last second of interval
        rem, ratio = totp_oracle.calculate_countdown(timestamp=329, step=step)
        assert rem == 1
        assert ratio == round(1 / 30, 4)

    def test_base32_input_normalization(self, totp_oracle: Type[TotpOracle]):
        """Verifies Base32 normalizer handles spaces, hyphens, lowercase, and optional padding."""
        canonical = "JBSWY3DPEHPK3PXP"
        variations = [
            "jbswy3dpehpk3pxp",  # lowercase
            "JBSW Y3DP EHPK 3PXP",  # spaces
            "JBSW-Y3DP-EHPK-3PXP",  # hyphens
            "JBSWY3DPEHPK3PXP====",  # explicit padding
            "  jbsw-y3dp ehpk 3pxp==  ",  # combination
        ]

        expected_bytes = totp_oracle.sanitize_base32(canonical)
        for var in variations:
            assert totp_oracle.sanitize_base32(var) == expected_bytes, f"Failed to normalize variation: '{var}'"
