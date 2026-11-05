//! AuthDesk - Subsistema de generación y validación de contraseñas de un solo uso (OTP).
//! Incluye soporte para Base32 RFC 4648, TOTP RFC 6238 y HOTP RFC 4226.

pub mod base32;
pub mod totp;

pub use self::base32::{decode_base32, normalize_base32};
pub use self::totp::{
    calculate_remaining_seconds, generate_hotp, generate_totp, generate_totp_from_bytes,
    generate_totp_now,
};
