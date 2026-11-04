"""Tier 5: Adversarial Empirical Stress Tests - Phase 1 TOTP & Base32 Engine.

Empirical verification of:
1. RFC 6238 Appendix B test vectors across SHA1, SHA256, SHA512 (6 & 8 digits).
2. Leading zero preservation at T=1234567890 ('005924').
3. Parity with default test accounts in AppState (GitHub, Google, AWS, Proton, Cloudflare)
   across multiple timestamps (59, 1111111109, 1111111111, 1234567890, 2000000000).
4. Base32 adversarial fuzzing: whitespace, lowercase, separators, non-zero trailing bits,
   invalid lengths (mod 8 in 1, 3, 6), invalid chars ('8', '9', '0', '1', punctuation, emojis).
5. Countdown boundary formulas: timestamp % step == 0 must yield step, never 0.
"""

from typing import Type
import pytest

from tests.e2e.oracle.totp_oracle import TotpOracle


@pytest.mark.tier(5)
@pytest.mark.milestone("M1")
class TestPhase1TotpAdversarial:
    """Adversarial challenge suite for TOTP Engine and Base32 logic."""

    def test_rfc6238_appendix_b_all_vectors(self, totp_oracle: Type[TotpOracle]):
        """Verifies exact 8-digit codes for SHA1, SHA256, SHA512 at all official timestamps."""
        for ts, counter_hex, exp_sha1, exp_sha256, exp_sha512 in totp_oracle.RFC_APPENDIX_B_VECTORS:
            c1 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA1"], ts, step=30, digits=8, algorithm="SHA1"
            )
            c256 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA256"], ts, step=30, digits=8, algorithm="SHA256"
            )
            c512 = totp_oracle.generate_totp(
                totp_oracle.RFC_TEST_SECRETS["SHA512"], ts, step=30, digits=8, algorithm="SHA512"
            )
            assert c1 == exp_sha1, f"SHA1 8d mismatch at T={ts}"
            assert c256 == exp_sha256, f"SHA256 8d mismatch at T={ts}"
            assert c512 == exp_sha512, f"SHA512 8d mismatch at T={ts}"

    def test_rfc6238_6_digit_double_zero_preservation(self, totp_oracle: Type[TotpOracle]):
        """Verifies 6-digit formatting and double zero preservation at T=1234567890."""
        code = totp_oracle.generate_totp(
            totp_oracle.RFC_TEST_SECRETS["SHA1"], 1234567890, step=30, digits=6, algorithm="SHA1"
        )
        assert code == "005924"
        assert len(code) == 6
        assert code.startswith("00")

    def test_default_test_accounts_oracle_parity(self, totp_oracle: Type[TotpOracle]):
        """Validates exact parity for AuthDesk's 5 default test accounts against the oracle."""
        accounts = [
            ("test-github-1", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30),
            ("test-google-2", "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "SHA1", 6, 30),
            ("test-aws-3", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30),
            ("test-proton-4", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====", "SHA256", 8, 30),
            (
                "test-cloudflare-5",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=",
                "SHA512",
                8,
                60,
            ),
        ]

        expected_matrix = {
            # (account_id, ts): (expected_code, expected_remaining)
            ("test-github-1", 59): ("996554", 1),
            ("test-github-1", 1111111109): ("071271", 1),
            ("test-github-1", 1111111111): ("358462", 29),
            ("test-github-1", 1234567890): ("742275", 30),
            ("test-github-1", 2000000000): ("890699", 10),
            ("test-google-2", 59): ("320382", 1),
            ("test-google-2", 1111111109): ("362012", 1),
            ("test-google-2", 1111111111): ("945476", 29),
            ("test-google-2", 1234567890): ("566657", 30),
            ("test-google-2", 2000000000): ("998128", 10),
            ("test-aws-3", 59): ("287082", 1),
            ("test-aws-3", 1111111109): ("081804", 1),
            ("test-aws-3", 1111111111): ("050471", 29),
            ("test-aws-3", 1234567890): ("005924", 30),
            ("test-aws-3", 2000000000): ("279037", 10),
            ("test-proton-4", 59): ("46119246", 1),
            ("test-proton-4", 1111111109): ("68084774", 1),
            ("test-proton-4", 1111111111): ("67062674", 29),
            ("test-proton-4", 1234567890): ("91819424", 30),
            ("test-proton-4", 2000000000): ("90698825", 10),
            ("test-cloudflare-5", 59): ("53550594", 1),
            ("test-cloudflare-5", 1111111109): ("37023009", 31),
            ("test-cloudflare-5", 1111111111): ("37023009", 29),
            ("test-cloudflare-5", 1234567890): ("85275929", 30),
            ("test-cloudflare-5", 2000000000): ("97791279", 40),
        }

        for acc_id, secret, algo, digits, step in accounts:
            for ts in [59, 1111111109, 1111111111, 1234567890, 2000000000]:
                code = totp_oracle.generate_totp(secret, ts, step=step, digits=digits, algorithm=algo)
                rem, _ = totp_oracle.calculate_countdown(ts, step=step)
                exp_code, exp_rem = expected_matrix[(acc_id, ts)]
                assert code == exp_code, f"Code mismatch for {acc_id} at T={ts}: got {code}, expected {exp_code}"
                assert rem == exp_rem, f"Countdown mismatch for {acc_id} at T={ts}: got {rem}, expected {exp_rem}"

    def test_base32_fuzzing_and_adversarial_inputs(self, totp_oracle: Type[TotpOracle]):
        """Adversarial stress on Base32 parser with spaces, hyphens, casing, and padding."""
        # Valid variations that must sanitize cleanly
        valid_variations = [
            "  JBSWY3DPEHPK3PXP  ",
            "jbswy3dpehpk3pxp",
            "JbSw-Y3dP-eHpK-3pXp",
            "JBSW Y3DP EHPK 3PXP====",
            "  jbsw-y3dp ehpk 3pxp==  ",
        ]
        canonical_bytes = totp_oracle.sanitize_base32("JBSWY3DPEHPK3PXP")
        for var in valid_variations:
            assert totp_oracle.sanitize_base32(var) == canonical_bytes

        # Invalid inputs that must be rejected
        invalid_inputs = [
            "",
            "   ",
            "---",
            "======",
            "JBSWY3DP8",  # '8' invalid
            "JBSWY3DP9",  # '9' invalid
            "JBSWY3DP0",  # '0' invalid
            "JBSWY3DP1",  # '1' invalid
            "JBSWY3DP!@#$",
            "JBSWY🔑DPEHPK3PXP",  # emoji
            "A",  # Invalid length (mod 8 == 1)
            "AAA",  # Invalid length (mod 8 == 3)
            "AAAAAA",  # Invalid length (mod 8 == 6)
        ]
        for inv in invalid_inputs:
            with pytest.raises(ValueError):
                totp_oracle.sanitize_base32(inv)

    def test_countdown_boundary_exact_seconds(self, totp_oracle: Type[TotpOracle]):
        """Validates that remaining seconds formula at t % step == 0 yields step, never 0."""
        for step in [15, 30, 45, 60, 90, 120, 300]:
            for multiplier in range(10):
                ts = multiplier * step
                rem, ratio = totp_oracle.calculate_countdown(ts, step=step)
                assert rem == step, f"At boundary T={ts}, step={step}: expected {step}, got {rem}"
                assert rem != 0, f"Remaining was 0 at boundary T={ts}"
                assert ratio == 1.0, f"Ratio was not 1.0 at boundary T={ts}"
