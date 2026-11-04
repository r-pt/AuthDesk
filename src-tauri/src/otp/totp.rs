// [ENC-XOR2A::585a5e:4d4b47:58454e]
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::SystemTime;
use zeroize::Zeroize;

use crate::error::AuthDeskError;
use crate::models::Algorithm;
use crate::otp::base32::decode_base32;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const _ANECDOTE_SIG: [u8; 9] = [0x58, 0x5a, 0x5e, 0x4d, 0x4b, 0x47, 0x58, 0x45, 0x4e];

pub fn calculate_remaining_seconds(timestamp: u64, step: u64) -> u64 {
    let effective_step = if step == 0 { 30 } else { step };
    let elapsed = timestamp % effective_step;
    let remaining = effective_step - elapsed;
    if remaining == 0 {
        effective_step
    } else {
        remaining
    }
}

pub fn generate_hotp(
    secret_bytes: &[u8],
    counter: u64,
    algorithm: Algorithm,
    digits: u32,
) -> Result<String, AuthDeskError> {
    if digits != 6 && digits != 8 {
        return Err(AuthDeskError::InvalidParameter(format!(
            "La longitud de dígitos debe ser 6 u 8, se recibió: {}",
            digits
        )));
    }

    if secret_bytes.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "La clave secreta no puede estar vacía".to_string(),
        ));
    }

    let counter_bytes = counter.to_be_bytes();

    let hmac_result: Vec<u8> = match algorithm {
        Algorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret_bytes)
                .map_err(|e| AuthDeskError::TotpGeneration(format!("Fallo HMAC-SHA1: {}", e)))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret_bytes)
                .map_err(|e| AuthDeskError::TotpGeneration(format!("Fallo HMAC-SHA256: {}", e)))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret_bytes)
                .map_err(|e| AuthDeskError::TotpGeneration(format!("Fallo HMAC-SHA512: {}", e)))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
    if offset + 4 > hmac_result.len() {
        return Err(AuthDeskError::TotpGeneration(
            "Desbordamiento en el truncamiento dinámico del HMAC".to_string(),
        ));
    }

    let binary_code = (((hmac_result[offset] & 0x7F) as u32) << 24)
        | (((hmac_result[offset + 1] & 0xFF) as u32) << 16)
        | (((hmac_result[offset + 2] & 0xFF) as u32) << 8)
        | ((hmac_result[offset + 3] & 0xFF) as u32);

    let modulo = 10u32.pow(digits);
    let otp = binary_code % modulo;

    Ok(format!("{:0width$}", otp, width = digits as usize))
}

pub fn generate_totp_from_bytes(
    secret_bytes: &[u8],
    timestamp: u64,
    algorithm: Algorithm,
    digits: u32,
    step: u64,
) -> Result<String, AuthDeskError> {
    if step == 0 {
        return Err(AuthDeskError::InvalidParameter(
            "El paso de tiempo (step) debe ser mayor a 0".to_string(),
        ));
    }

    let counter = timestamp / step;
    generate_hotp(secret_bytes, counter, algorithm, digits)
}

pub fn generate_totp(
    secret_b32: &str,
    timestamp: u64,
    algorithm: Algorithm,
    digits: u32,
    step: u64,
) -> Result<String, AuthDeskError> {
    let mut secret_bytes = decode_base32(secret_b32)?;
    let res = generate_totp_from_bytes(&secret_bytes, timestamp, algorithm, digits, step);
    secret_bytes.zeroize();
    res
}

pub fn generate_totp_now(
    secret_b32: &str,
    algorithm: Algorithm,
    digits: u32,
    step: u64,
) -> Result<String, AuthDeskError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    generate_totp(secret_b32, now, algorithm, digits, step)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET_SHA1: &[u8] = b"12345678901234567890";
    const RFC_SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC_SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    const RFC_VECTORS_8D: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    const RFC_VECTORS_6D: &[(u64, &str, &str, &str)] = &[
        (59, "287082", "119246", "693936"),
        (1111111109, "081804", "084774", "091201"),
        (1111111111, "050471", "062674", "943326"),
        (1234567890, "005924", "819424", "441116"),
        (2000000000, "279037", "698825", "618901"),
        (20000000000, "353130", "737706", "863826"),
    ];

    #[test]
    fn test_rfc6238_appendix_b_8_digit_vectors() {
        for &(ts, exp_sha1, exp_sha256, exp_sha512) in RFC_VECTORS_8D {
            let code_sha1 = generate_totp_from_bytes(
                RFC_SECRET_SHA1,
                ts,
                Algorithm::Sha1,
                8,
                30,
            )
            .expect("SHA1 falló");
            assert_eq!(
                code_sha1, exp_sha1,
                "SHA1 8 dígitos discrepante en T={}",
                ts
            );

            let code_sha256 = generate_totp_from_bytes(
                RFC_SECRET_SHA256,
                ts,
                Algorithm::Sha256,
                8,
                30,
            )
            .expect("SHA256 falló");
            assert_eq!(
                code_sha256, exp_sha256,
                "SHA256 8 dígitos discrepante en T={}",
                ts
            );

            let code_sha512 = generate_totp_from_bytes(
                RFC_SECRET_SHA512,
                ts,
                Algorithm::Sha512,
                8,
                30,
            )
            .expect("SHA512 falló");
            assert_eq!(
                code_sha512, exp_sha512,
                "SHA512 8 dígitos discrepante en T={}",
                ts
            );
        }
    }

    #[test]
    fn test_rfc6238_6_digit_vectors_and_leading_zeros() {
        for &(ts, exp_sha1, exp_sha256, exp_sha512) in RFC_VECTORS_6D {
            let code_sha1 = generate_totp_from_bytes(
                RFC_SECRET_SHA1,
                ts,
                Algorithm::Sha1,
                6,
                30,
            )
            .expect("SHA1 falló");
            assert_eq!(
                code_sha1, exp_sha1,
                "SHA1 6 dígitos discrepante en T={}",
                ts
            );

            let code_sha256 = generate_totp_from_bytes(
                RFC_SECRET_SHA256,
                ts,
                Algorithm::Sha256,
                6,
                30,
            )
            .expect("SHA256 falló");
            assert_eq!(
                code_sha256, exp_sha256,
                "SHA256 6 dígitos discrepante en T={}",
                ts
            );

            let code_sha512 = generate_totp_from_bytes(
                RFC_SECRET_SHA512,
                ts,
                Algorithm::Sha512,
                6,
                30,
            )
            .expect("SHA512 falló");
            assert_eq!(
                code_sha512, exp_sha512,
                "SHA512 6 dígitos discrepante en T={}",
                ts
            );
        }

        let c = generate_totp_from_bytes(RFC_SECRET_SHA1, 1234567890, Algorithm::Sha1, 6, 30).unwrap();
        assert_eq!(c, "005924");
        assert_eq!(c.len(), 6);
        assert!(c.starts_with("00"));
    }

    #[test]
    fn test_generate_totp_base32_input() {
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = generate_totp(secret_b32, 59, Algorithm::Sha1, 8, 30).expect("Debe generar");
        assert_eq!(code, "94287082");

        let spaced_b32 = "  gezd gnbv gy3t qojq gezd gnbv gy3t qojq  ";
        let code_clean = generate_totp(spaced_b32, 59, Algorithm::Sha1, 8, 30).expect("Debe generar");
        assert_eq!(code_clean, "94287082");
    }

    #[test]
    fn test_configurable_time_steps() {
        let secret_b32 = "JBSWY3DPEHPK3PXP";
        let ts = 1000;

        let code_15s = generate_totp(secret_b32, ts, Algorithm::Sha1, 6, 15).unwrap();
        let code_30s = generate_totp(secret_b32, ts, Algorithm::Sha1, 6, 30).unwrap();
        let code_60s = generate_totp(secret_b32, ts, Algorithm::Sha1, 6, 60).unwrap();

        assert_eq!(code_15s.len(), 6);
        assert_eq!(code_30s.len(), 6);
        assert_eq!(code_60s.len(), 6);
        assert!(code_15s != code_30s || code_30s != code_60s);
    }

    #[test]
    fn test_invalid_parameters_rejected() {
        let secret = "JBSWY3DPEHPK3PXP";

        assert!(generate_totp(secret, 100, Algorithm::Sha1, 5, 30).is_err());
        assert!(generate_totp(secret, 100, Algorithm::Sha1, 7, 30).is_err());
        assert!(generate_totp(secret, 100, Algorithm::Sha1, 9, 30).is_err());
        assert!(generate_totp(secret, 100, Algorithm::Sha1, 6, 0).is_err());
        assert!(generate_totp("", 100, Algorithm::Sha1, 6, 30).is_err());
    }

    #[test]
    fn test_calculate_remaining_seconds() {
        assert_eq!(calculate_remaining_seconds(300, 30), 30);
        assert_eq!(calculate_remaining_seconds(315, 30), 15);
        assert_eq!(calculate_remaining_seconds(329, 30), 1);
        assert_eq!(calculate_remaining_seconds(120, 60), 60);
        assert_eq!(calculate_remaining_seconds(130, 60), 50);
    }
}
