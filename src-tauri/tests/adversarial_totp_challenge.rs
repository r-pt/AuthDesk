//! Adversarial Challenge Test Suite for AuthDesk TOTP Engine & Base32 Logic
//! Tests RFC 6238 Appendix B vectors, Base32 fuzzing, countdown boundaries,
//! memory safety, error message sanitization, and default test accounts.

use authdesk_lib::models::Algorithm;
use authdesk_lib::otp::base32::{decode_base32, normalize_base32};
use authdesk_lib::otp::totp::{
    calculate_remaining_seconds, generate_totp, generate_totp_from_bytes,
};
use authdesk_lib::state::AppState;

// =========================================================================
// 1. RFC 6238 Appendix B Test Vectors
// =========================================================================

const RFC_SECRET_SHA1: &[u8] = b"12345678901234567890"; // 20 bytes
const RFC_SECRET_SHA256: &[u8] = b"12345678901234567890123456789012"; // 32 bytes
const RFC_SECRET_SHA512: &[u8] =
    b"1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes

// (timestamp, sha1_8, sha256_8, sha512_8)
const RFC_APPENDIX_B_8D: &[(u64, &str, &str, &str)] = &[
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
];

// (timestamp, sha1_6, sha256_6, sha512_6)
const RFC_DERIVED_6D: &[(u64, &str, &str, &str)] = &[
    (59, "287082", "119246", "693936"),
    (1111111109, "081804", "084774", "091201"),
    (1111111111, "050471", "062674", "943326"),
    (1234567890, "005924", "819424", "441116"), // Double leading zero test
    (2000000000, "279037", "698825", "618901"),
    (20000000000, "353130", "737706", "863826"),
];

#[test]
fn test_rfc6238_8_digit_exact_matches() {
    for &(ts, exp_sha1, exp_sha256, exp_sha512) in RFC_APPENDIX_B_8D {
        let s1 = generate_totp_from_bytes(RFC_SECRET_SHA1, ts, Algorithm::Sha1, 8, 30)
            .expect("SHA1 8d error");
        assert_eq!(s1, exp_sha1, "SHA1 8d mismatch at T={}", ts);

        let s256 = generate_totp_from_bytes(RFC_SECRET_SHA256, ts, Algorithm::Sha256, 8, 30)
            .expect("SHA256 8d error");
        assert_eq!(s256, exp_sha256, "SHA256 8d mismatch at T={}", ts);

        let s512 = generate_totp_from_bytes(RFC_SECRET_SHA512, ts, Algorithm::Sha512, 8, 30)
            .expect("SHA512 8d error");
        assert_eq!(s512, exp_sha512, "SHA512 8d mismatch at T={}", ts);
    }
}

#[test]
fn test_rfc6238_6_digit_exact_matches_and_leading_zeros() {
    for &(ts, exp_sha1, exp_sha256, exp_sha512) in RFC_DERIVED_6D {
        let s1 = generate_totp_from_bytes(RFC_SECRET_SHA1, ts, Algorithm::Sha1, 6, 30)
            .expect("SHA1 6d error");
        assert_eq!(s1, exp_sha1, "SHA1 6d mismatch at T={}", ts);

        let s256 = generate_totp_from_bytes(RFC_SECRET_SHA256, ts, Algorithm::Sha256, 6, 30)
            .expect("SHA256 6d error");
        assert_eq!(s256, exp_sha256, "SHA256 6d mismatch at T={}", ts);

        let s512 = generate_totp_from_bytes(RFC_SECRET_SHA512, ts, Algorithm::Sha512, 6, 30)
            .expect("SHA512 6d error");
        assert_eq!(s512, exp_sha512, "SHA512 6d mismatch at T={}", ts);
    }

    // Specific verification of double leading zero at T=1234567890
    let code_005924 = generate_totp_from_bytes(RFC_SECRET_SHA1, 1234567890, Algorithm::Sha1, 6, 30)
        .expect("Code generation failed");
    assert_eq!(code_005924, "005924");
    assert_eq!(code_005924.len(), 6);
    assert_eq!(&code_005924[0..2], "00");
}

// =========================================================================
// 2. Base32 Sanitization, Normalization, & Fuzzing
// =========================================================================

#[test]
fn test_base32_whitespace_separators_and_casing() {
    let canonical = "JBSWY3DPEHPK3PXP";
    let valid_variations = vec![
        "JBSWY3DPEHPK3PXP",
        "jbswy3dpehpk3pxp",
        "JbSwY3dPeHpK3pXp",
        "  JBSWY3DPEHPK3PXP  ",
        "JBSW Y3DP EHPK 3PXP",
        "JBSW-Y3DP-EHPK-3PXP",
        " \t JBSW-Y3DP \n EHPK-3PXP \r\n ",
        "jbsw-y3dp-ehpk-3pxp",
        "JBSWY3DPEHPK3PXP====",
        "jbswy3dpehpk3pxp====",
        "  JBSW Y3DP-EHPK 3PXP====  ",
    ];

    let expected_bytes = b"Hello!\xde\xad\xbe\xef";

    for var in valid_variations {
        let decoded = decode_base32(var).unwrap_or_else(|e| {
            panic!("Failed to decode valid variation '{}': {:?}", var, e)
        });
        assert_eq!(
            decoded.as_slice(),
            expected_bytes,
            "Decoded bytes mismatch for '{}'",
            var
        );

        let normalized = normalize_base32(var).expect("Failed normalize");
        assert_eq!(
            normalized, canonical,
            "Normalized mismatch for variation '{}'",
            var
        );
    }
}

#[test]
fn test_base32_padding_tolerance() {
    // Official RFC 4648 Base32 test vectors:
    // BASE32("") = ""
    // BASE32("f") = "MY======"
    // BASE32("fo") = "MZXQ====" (4 chars)
    // BASE32("foo") = "MZXW6===" (5 chars)
    // BASE32("foob") = "MZXW6YQ=" (7 chars)
    // BASE32("fooba") = "MZXW6YTB" (8 chars)
    // BASE32("foobar") = "MZXW6YTBOI======"
    let cases = [
        ("", false, b"".as_slice()), // Empty string must be rejected
        ("MY", true, b"f".as_slice()),
        ("MY======", true, b"f".as_slice()),
        ("my", true, b"f".as_slice()),
        ("MZXQ", true, b"fo".as_slice()),
        ("MZXQ====", true, b"fo".as_slice()),
        ("mzxq", true, b"fo".as_slice()),
        ("MZXW6", true, b"foo".as_slice()),
        ("MZXW6===", true, b"foo".as_slice()),
        ("MZXW6YQ", true, b"foob".as_slice()),
        ("MZXW6YQ=", true, b"foob".as_slice()),
        ("MZXW6YTB", true, b"fooba".as_slice()),
        ("MZXW6YTBOI======", true, b"foobar".as_slice()),
        ("mzxw6ytboi", true, b"foobar".as_slice()),
    ];

    for (input, should_succeed, expected) in cases {
        let res = decode_base32(input);
        if should_succeed {
            assert!(
                res.is_ok(),
                "Expected success for '{}', got error {:?}",
                input,
                res.err()
            );
            assert_eq!(res.unwrap(), expected, "Decoded content mismatch for '{}'", input);
        } else {
            assert!(res.is_err(), "Expected failure for input '{}'", input);
        }
    }
}

#[test]
fn test_base32_non_zero_trailing_bits_and_invalid_lengths() {
    // RFC 4648 Section 6 specifies that unpadded lengths cannot be 1, 3, or 6:
    // Length 1 (e.g. "A"): 5 bits -> cannot form 8-bit byte
    assert!(decode_base32("A").is_err(), "Length 1 must fail decode");
    assert!(decode_base32("A=======").is_err(), "Length 1 padded must fail decode");

    // Length 3 (e.g. "AAA"): 15 bits -> cannot form valid Base32 boundary
    assert!(decode_base32("AAA").is_err(), "Length 3 must fail decode");
    assert!(decode_base32("AAA=====").is_err(), "Length 3 padded must fail decode");

    // Length 6 (e.g. "AAAAAA"): 30 bits -> cannot form valid Base32 boundary
    assert!(decode_base32("AAAAAA").is_err(), "Length 6 must fail decode");
    assert!(decode_base32("AAAAAA==").is_err(), "Length 6 padded must fail decode");

    // Non-zero trailing bits rejection:
    // "MZXW" instead of "MZXQ": 'W' has trailing non-zero bits for length 4
    assert!(
        decode_base32("MZXW").is_err(),
        "Non-zero trailing bits in 'MZXW' must fail decode"
    );
    assert!(
        decode_base32("MZXW====").is_err(),
        "Non-zero trailing bits in 'MZXW====' must fail decode"
    );
}

#[test]
fn test_base32_rejection_of_invalid_characters() {
    let invalid_inputs = [
        "JBSWY3DP8",           // '8' is not in base32
        "JBSWY3DP9",           // '9' is not in base32
        "JBSWY3DP0",           // '0' is not in base32
        "JBSWY3DP1",           // '1' is not in base32
        "JBSWY3DP!",           // Exclamation
        "JBSWY#DPEHPK3PXP",    // Hash
        "JBSWY@DPEHPK3PXP",    // At symbol
        "JBSWY$DPEHPK3PXP",    // Dollar
        "JBSWY%DPEHPK3PXP",    // Percent
        "JBSWY^DPEHPK3PXP",    // Caret
        "JBSWY&DPEHPK3PXP",    // Ampersand
        "JBSWY*DPEHPK3PXP",    // Asterisk
        "JBSWY(DPEHPK3PXP",    // Paren
        "JBSWY_DPEHPK3PXP",    // Underscore
        "JBSWY+DPEHPK3PXP",    // Plus
        "JBSWY=DPEHPK3PXP",    // Equal in the middle of data
        "JBSWY.DPEHPK3PXP",    // Dot
        "JBSWY/DPEHPK3PXP",    // Slash
        "JBSWY?DPEHPK3PXP",    // Question mark
        "JBSWY<DPEHPK3PXP",    // Less than
        "JBSWY>DPEHPK3PXP",    // Greater than
        "JBSWY[DPEHPK3PXP",    // Bracket
        "JBSWY]DPEHPK3PXP",    // Bracket
        "JBSWY{DPEHPK3PXP",    // Brace
        "JBSWY}DPEHPK3PXP",    // Brace
        "JBSWY|DPEHPK3PXP",    // Pipe
        "JBSWY~DPEHPK3PXP",    // Tilde
        "JBSWY`DPEHPK3PXP",    // Backtick
        "JBSWY🔑DPEHPK3PXP",    // Unicode emoji (Key)
        "JBSWYñDPEHPK3PXP",    // Spanish accented char
        "JBSWYéDPEHPK3PXP",    // Accented char
        "JBSWYüDPEHPK3PXP",    // Umlaut
        "   ",                 // Only spaces
        "\t\n\r",              // Only whitespace
        "---",                 // Only hyphens
        "========",            // Only padding
        "  - - ==  ",          // Mixed whitespace/hyphens/padding without data
    ];

    for inv in invalid_inputs {
        let res = decode_base32(inv);
        assert!(
            res.is_err(),
            "Expected failure for invalid input: {:?}, got Ok",
            inv
        );

        // Security requirement: Ensure the error message does not expose raw secret data
        let err_str = res.err().unwrap().to_string();
        if !inv.trim().is_empty() && inv.len() > 10 {
            assert!(
                !err_str.contains(inv),
                "Error message exposed sensitive input string! Error: {}",
                err_str
            );
        }
    }
}

// =========================================================================
// 3. Countdown and Period Boundaries
// =========================================================================

#[test]
fn test_countdown_exact_boundary_seconds() {
    // Invariant: At timestamp % step == 0, remaining seconds MUST yield step, NEVER 0.
    for step in [15u64, 30u64, 45u64, 60u64, 90u64, 120u64, 300u64] {
        for multiplier in 0..10u64 {
            let boundary_ts = multiplier * step;
            let remaining = calculate_remaining_seconds(boundary_ts, step);
            assert_eq!(
                remaining, step,
                "Boundary failed for step={} at T={}: expected {}, got {}",
                step, boundary_ts, step, remaining
            );
            assert_ne!(
                remaining, 0,
                "CRITICAL: remaining seconds was 0 at boundary T={}",
                boundary_ts
            );
        }
    }
}

#[test]
fn test_countdown_step_progression() {
    let step = 30u64;
    let base_ts = 300u64; // multiple of 30

    // Test each second through a full 30-second cycle:
    // T = 300 -> 30
    // T = 301 -> 29
    // ...
    // T = 329 -> 1
    // T = 330 -> 30
    for elapsed in 0..step {
        let ts = base_ts + elapsed;
        let rem = calculate_remaining_seconds(ts, step);
        let expected = if elapsed == 0 { step } else { step - elapsed };
        assert_eq!(
            rem, expected,
            "Progression mismatch at elapsed={}: got {}, expected {}",
            elapsed, rem, expected
        );
    }
}

#[test]
fn test_period_comparison_30s_vs_60s() {
    let secret = "JBSWY3DPEHPK3PXP";

    // At T=0..29: both are in their first interval
    let c30_0 = generate_totp(secret, 0, Algorithm::Sha1, 6, 30).unwrap();
    let c60_0 = generate_totp(secret, 0, Algorithm::Sha1, 6, 60).unwrap();
    // Counter is 0 for both, so codes must be equal at T=0
    assert_eq!(c30_0, c60_0, "At T=0, counter=0 for both steps -> codes should match");

    // At T=35:
    // 30s has counter = 35 / 30 = 1
    // 60s has counter = 35 / 60 = 0
    let c30_35 = generate_totp(secret, 35, Algorithm::Sha1, 6, 30).unwrap();
    let c60_35 = generate_totp(secret, 35, Algorithm::Sha1, 6, 60).unwrap();

    // 60s code must still match T=0
    assert_eq!(c60_35, c60_0, "60s code must be unchanged at T=35");
    // 30s code must have changed
    assert_ne!(c30_35, c30_0, "30s code must have changed at T=35");
    // 30s and 60s must differ
    assert_ne!(c30_35, c60_35, "30s and 60s codes must differ at T=35");

    // Countdown check at T=45:
    // 30s: 45 % 30 = 15 elapsed -> 15 remaining
    // 60s: 45 % 60 = 45 elapsed -> 15 remaining
    assert_eq!(calculate_remaining_seconds(45, 30), 15);
    assert_eq!(calculate_remaining_seconds(45, 60), 15);

    // Countdown check at T=75:
    // 30s: 75 % 30 = 15 elapsed -> 15 remaining
    // 60s: 75 % 60 = 15 elapsed -> 45 remaining
    assert_eq!(calculate_remaining_seconds(75, 30), 15);
    assert_eq!(calculate_remaining_seconds(75, 60), 45);
}

// =========================================================================
// 4. Default Test Accounts Parity in AppState
// =========================================================================

#[test]
fn test_default_test_accounts_totp_parity() {
    let state = AppState::with_accounts(AppState::default_test_accounts());

    // Accounts defined in default_test_accounts:
    // 1. GitHub: "JBSWY3DPEHPK3PXP", Sha1, 6d, 30s
    // 2. Google: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", Sha1, 6d, 30s
    // 3. AWS: RFC 20B "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Sha1, 6d, 30s
    // 4. Proton: RFC 32B "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====", Sha256, 8d, 30s
    // 5. Cloudflare: RFC 64B "...", Sha512, 8d, 60s

    // Test at T=1234567890:
    let codes = state.get_codes_at(1234567890).expect("Get codes at T=1234567890");

    let aws = codes.iter().find(|c| c.id == "test-aws-3").expect("AWS account");
    assert_eq!(aws.code, "005924", "AWS 6d code at T=1234567890");
    assert_eq!(aws.digits, 6);
    assert_eq!(aws.seconds_remaining, 30); // 1234567890 % 30 == 0 -> 30 remaining

    let proton = codes.iter().find(|c| c.id == "test-proton-4").expect("Proton account");
    assert_eq!(proton.code, "91819424", "Proton 8d code at T=1234567890");
    assert_eq!(proton.digits, 8);
    assert_eq!(proton.seconds_remaining, 30);

    let cf = codes.iter().find(|c| c.id == "test-cloudflare-5").expect("Cloudflare account");
    assert_eq!(cf.digits, 8);
    assert_eq!(cf.period, 60);
    // At T=1234567890, 1234567890 % 60 = 30 -> 60 - 30 = 30 remaining
    assert_eq!(cf.seconds_remaining, 30);

    // Test at T=59:
    let codes_59 = state.get_codes_at(59).expect("Get codes at T=59");
    let aws_59 = codes_59.iter().find(|c| c.id == "test-aws-3").unwrap();
    // At T=59, RFC 6d SHA1 is "287082"
    assert_eq!(aws_59.code, "287082");
    assert_eq!(aws_59.seconds_remaining, 1); // 59 % 30 = 29 -> 1 remaining

    let proton_59 = codes_59.iter().find(|c| c.id == "test-proton-4").unwrap();
    // At T=59, RFC 8d SHA256 is "46119246"
    assert_eq!(proton_59.code, "46119246");
    assert_eq!(proton_59.seconds_remaining, 1);
}

// =========================================================================
// 5. Parameter Validation & Edge Case Rejection
// =========================================================================

#[test]
fn test_invalid_parameters_robustly_rejected() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";

    // Invalid digits: must be 6 or 8
    for d in [0, 1, 4, 5, 7, 9, 10, 12] {
        let res = generate_totp(secret_b32, 1000, Algorithm::Sha1, d, 30);
        assert!(res.is_err(), "Expected error for digits={}", d);
    }

    // Step = 0 must be rejected
    let res_step0 = generate_totp(secret_b32, 1000, Algorithm::Sha1, 6, 0);
    assert!(res_step0.is_err(), "Expected error for step=0");

    // Empty secret in generate_totp
    assert!(generate_totp("", 1000, Algorithm::Sha1, 6, 30).is_err());
    assert!(generate_totp("   ", 1000, Algorithm::Sha1, 6, 30).is_err());

    // Empty secret bytes in generate_totp_from_bytes
    assert!(generate_totp_from_bytes(&[], 1000, Algorithm::Sha1, 6, 30).is_err());
}
