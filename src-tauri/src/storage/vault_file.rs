// [ENC-B64::cnB0|Z2Ft|cm9k]
use serde::{Deserialize, Serialize};
use data_encoding::BASE64;
use crate::error::AuthDeskError;
use crate::models::Account;

pub const VAULT_MAGIC: &str = "AUTHDESK_VAULT";
pub const VAULT_VERSION: u32 = 1;
pub const KDF_ALGO_ARGON2ID: &str = "Argon2id";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfConfig {
    pub algorithm: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub magic: String,
    pub version: u32,
    pub created_at: i64,
    pub updated_at: i64,
    pub kdf: KdfConfig,
    pub wrapped_master_key: EncryptedBlob,
    pub payload: EncryptedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub version: u32,
    pub accounts: Vec<Account>,
}

impl VaultEnvelope {
    pub fn validate(&self) -> Result<(), AuthDeskError> {
        if self.magic != VAULT_MAGIC {
            return Err(AuthDeskError::Vault(format!(
                "Invalid magic header: expected '{}', got '{}'",
                VAULT_MAGIC, self.magic
            )));
        }

        if self.version != VAULT_VERSION {
            return Err(AuthDeskError::Vault(format!(
                "Unsupported vault version: expected {}, got {}",
                VAULT_VERSION, self.version
            )));
        }

        if self.created_at <= 0 || self.updated_at <= 0 {
            return Err(AuthDeskError::Vault(
                "Invalid envelope timestamps: must be positive unix timestamps".to_string(),
            ));
        }

        if self.kdf.algorithm != KDF_ALGO_ARGON2ID {
            return Err(AuthDeskError::Vault(format!(
                "Invalid KDF algorithm: expected '{}', got '{}'",
                KDF_ALGO_ARGON2ID, self.kdf.algorithm
            )));
        }

        if self.kdf.m_cost_kib < 65536 {
            return Err(AuthDeskError::Vault(format!(
                "Invalid KDF m_cost: expected at least 65536 KiB, got {}",
                self.kdf.m_cost_kib
            )));
        }

        if self.kdf.t_cost < 3 {
            return Err(AuthDeskError::Vault(format!(
                "Invalid KDF t_cost: expected at least 3, got {}",
                self.kdf.t_cost
            )));
        }

        if self.kdf.p_cost != 1 {
            return Err(AuthDeskError::Vault(format!(
                "Invalid KDF p_cost: expected 1, got {}",
                self.kdf.p_cost
            )));
        }

        let salt = BASE64
            .decode(self.kdf.salt_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(format!("Invalid KDF salt_b64 encoding: {}", e)))?;
        if salt.len() < 16 {
            return Err(AuthDeskError::Vault(format!(
                "Salt too short: expected at least 16 bytes, got {}",
                salt.len()
            )));
        }

        let mk_nonce = BASE64
            .decode(self.wrapped_master_key.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(format!("Invalid wrapped MK nonce encoding: {}", e)))?;
        if mk_nonce.len() != 24 {
            return Err(AuthDeskError::Vault(format!(
                "Wrapped MK nonce length mismatch: expected 24, got {}",
                mk_nonce.len()
            )));
        }

        let mk_ct = BASE64
            .decode(self.wrapped_master_key.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(format!("Invalid wrapped MK ciphertext encoding: {}", e)))?;
        if mk_ct.len() != 48 {
            return Err(AuthDeskError::Vault(format!(
                "Wrapped MK ciphertext length mismatch: expected 48, got {}",
                mk_ct.len()
            )));
        }

        let p_nonce = BASE64
            .decode(self.payload.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(format!("Invalid payload nonce encoding: {}", e)))?;
        if p_nonce.len() != 24 {
            return Err(AuthDeskError::Vault(format!(
                "Payload nonce length mismatch: expected 24, got {}",
                p_nonce.len()
            )));
        }

        let p_ct = BASE64
            .decode(self.payload.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(format!("Invalid payload ciphertext encoding: {}", e)))?;
        if p_ct.len() < 16 {
            return Err(AuthDeskError::Vault(format!(
                "Payload ciphertext too short: expected at least 16, got {}",
                p_ct.len()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_envelope() -> VaultEnvelope {
        VaultEnvelope {
            magic: "AUTHDESK_VAULT".to_string(),
            version: 1,
            created_at: 1710000000,
            updated_at: 1710000000,
            kdf: KdfConfig {
                algorithm: "Argon2id".to_string(),
                m_cost_kib: 65536,
                t_cost: 3,
                p_cost: 1,
                salt_b64: BASE64.encode(&[0u8; 32]),
            },
            wrapped_master_key: EncryptedBlob {
                nonce_b64: BASE64.encode(&[0u8; 24]),
                ciphertext_b64: BASE64.encode(&[0u8; 48]),
            },
            payload: EncryptedBlob {
                nonce_b64: BASE64.encode(&[0u8; 24]),
                ciphertext_b64: BASE64.encode(&[0u8; 64]),
            },
        }
    }

    #[test]
    fn test_envelope_validation_success() {
        let env = valid_envelope();
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_envelope_validation_rejects_corrupted_magic() {
        let mut env = valid_envelope();
        env.magic = "INVALID_MAGIC".to_string();
        assert!(env.validate().is_err());
    }

    #[test]
    fn test_envelope_validation_rejects_downgrade() {
        let mut env = valid_envelope();
        env.kdf.m_cost_kib = 1024;
        assert!(env.validate().is_err());
    }
}
