// [ENC-B64::cnB0|Z2Ft|cm9k]
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::AuthDeskError;

pub const DEFAULT_M_COST_KIB: u32 = 65536;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;
pub const MIN_SALT_LEN: usize = 16;
pub const RECOMMENDED_SALT_LEN: usize = 32;
pub const KEK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

pub struct DerivedKek {
    pub(crate) key: [u8; 32],
}

impl DerivedKek {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Clone for DerivedKek {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Zeroize for DerivedKek {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for DerivedKek {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DerivedKek {}

impl std::fmt::Debug for DerivedKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedKek([REDACTED])")
    }
}

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn validate_kdf_params(params: &Argon2Params, salt_len: usize) -> Result<(), AuthDeskError> {
    if params.m_cost_kib < 65536 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF m_cost: expected at least 65536 KiB, got {}",
            params.m_cost_kib
        )));
    }
    if params.t_cost < 3 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF t_cost: expected at least 3, got {}",
            params.t_cost
        )));
    }
    if params.p_cost != 1 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF p_cost: expected 1, got {}",
            params.p_cost
        )));
    }
    if salt_len < MIN_SALT_LEN {
        return Err(AuthDeskError::Vault(format!(
            "Salt too short: expected at least {} bytes, got {}",
            MIN_SALT_LEN, salt_len
        )));
    }
    Ok(())
}

pub fn derive_kek(
    password: &str,
    salt: &[u8],
    params: &Argon2Params,
) -> Result<DerivedKek, AuthDeskError> {
    validate_kdf_params(params, salt.len())?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEK_LEN),
    )
    .map_err(|e| AuthDeskError::Vault(format!("Invalid Argon2id parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| AuthDeskError::Vault(format!("Argon2id derivation failed: {}", e)))?;

    Ok(DerivedKek::new(key))
}

pub fn derive_pin_kek(
    pin: &str,
    salt: &[u8],
    device_key: &[u8; 32],
    params: &Argon2Params,
) -> Result<DerivedKek, AuthDeskError> {
    validate_kdf_params(params, salt.len())?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEK_LEN),
    )
    .map_err(|e| AuthDeskError::Vault(format!("Invalid Argon2id parameters: {}", e)))?;

    let argon2 = Argon2::new_with_secret(
        device_key,
        Algorithm::Argon2id,
        Version::V0x13,
        argon_params,
    )
    .map_err(|e| AuthDeskError::Vault(format!("Argon2id new_with_secret failed: {}", e)))?;

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut key)
        .map_err(|e| AuthDeskError::Vault(format!("Argon2id derivation failed: {}", e)))?;

    Ok(DerivedKek::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_pin_kek_secret_sensitivity() {
        let params = Argon2Params::default();
        let salt = [0x55u8; 32];
        let dk1 = [0x11u8; 32];
        let dk2 = [0x22u8; 32];
        let pin = "123456";

        let k1 = derive_pin_kek(pin, &salt, &dk1, &params).unwrap();
        let k2 = derive_pin_kek(pin, &salt, &dk1, &params).unwrap();
        let k3 = derive_pin_kek(pin, &salt, &dk2, &params).unwrap();
        let k4 = derive_pin_kek("654321", &salt, &dk1, &params).unwrap();

        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert_ne!(k1.as_bytes(), k3.as_bytes());
        assert_ne!(k1.as_bytes(), k4.as_bytes());
    }


    #[test]
    fn test_kdf_determinism_and_salt_sensitivity() {
        let params = Argon2Params::default();
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];

        let k1 = derive_kek("correct-horse-battery-staple", &salt1, &params).unwrap();
        let k2 = derive_kek("correct-horse-battery-staple", &salt1, &params).unwrap();
        let k3 = derive_kek("correct-horse-battery-staple", &salt2, &params).unwrap();

        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert_ne!(k1.as_bytes(), k3.as_bytes());
    }

    #[test]
    fn test_kdf_params_validation_rejects_downgrade() {
        let mut p = Argon2Params::default();
        p.m_cost_kib = 1024;
        assert!(validate_kdf_params(&p, 32).is_err());

        let mut p = Argon2Params::default();
        p.t_cost = 2;
        assert!(validate_kdf_params(&p, 32).is_err());

        let mut p = Argon2Params::default();
        p.p_cost = 2;
        assert!(validate_kdf_params(&p, 32).is_err());

        let p = Argon2Params::default();
        assert!(validate_kdf_params(&p, 8).is_err());
    }

    #[test]
    fn test_derived_kek_debug_redacted() {
        let kek = DerivedKek::new([42u8; 32]);
        let debug = format!("{:?}", kek);
        assert_eq!(debug, "DerivedKek([REDACTED])");
        assert!(!debug.contains("42"));
    }
}
