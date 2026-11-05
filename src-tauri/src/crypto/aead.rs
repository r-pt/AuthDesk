// [ENC-B64::cnB0|Z2Ft|cm9k]
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::kdf::DerivedKek;
use crate::error::AuthDeskError;

pub struct MasterKey {
    pub(crate) key: [u8; 32],
}

impl MasterKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn generate_master_key() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MasterKey {}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

pub fn generate_master_key() -> MasterKey {
    MasterKey::generate_master_key()
}

pub fn compute_wrapped_key_aad(
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(15 + 16 + salt.len());
    aad.extend_from_slice(b"AUTHDESK_MK_V1:");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&m_cost.to_be_bytes());
    aad.extend_from_slice(&t_cost.to_be_bytes());
    aad.extend_from_slice(&p_cost.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

pub fn compute_payload_aad(version: u32, updated_at: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20 + 4 + 8);
    aad.extend_from_slice(b"AUTHDESK_PAYLOAD_V1:");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&updated_at.to_be_bytes());
    aad
}

pub fn encrypt_master_key(
    master_key: &MasterKey,
    kek: &DerivedKek,
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), AuthDeskError> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_bytes()));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: master_key.as_bytes(),
                aad,
            },
        )
        .map_err(|_| AuthDeskError::Vault("Master key encryption failed".to_string()))?;

    Ok((ct, nonce))
}

pub fn decrypt_master_key(
    ciphertext: &[u8],
    nonce: &[u8; 24],
    kek: &DerivedKek,
    aad: &[u8],
) -> Result<MasterKey, AuthDeskError> {
    if ciphertext.len() != 48 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid wrapped master key ciphertext length: expected 48, got {}",
            ciphertext.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_bytes()));
    let mut pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AuthDeskError::Vault("Authentication failed for wrapped master key".to_string()))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&pt[..32]);
    pt.zeroize();
    Ok(MasterKey::new(key))
}

pub fn encrypt_payload(
    plaintext: &[u8],
    master_key: &MasterKey,
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), AuthDeskError> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.as_bytes()));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AuthDeskError::Vault("Payload encryption failed".to_string()))?;

    Ok((ct, nonce))
}

pub fn decrypt_payload(
    ciphertext: &[u8],
    nonce: &[u8; 24],
    master_key: &MasterKey,
    aad: &[u8],
) -> Result<Vec<u8>, AuthDeskError> {
    if ciphertext.len() < 16 {
        return Err(AuthDeskError::Vault(format!(
            "Payload ciphertext too short: expected at least 16 bytes, got {}",
            ciphertext.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.as_bytes()));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AuthDeskError::Vault("Authentication failed for payload ciphertext".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_debug_redacted() {
        let mk = MasterKey::new([99u8; 32]);
        let debug = format!("{:?}", mk);
        assert_eq!(debug, "MasterKey([REDACTED])");
        assert!(!debug.contains("99"));
    }

    #[test]
    fn test_master_key_encrypt_decrypt_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let kek = DerivedKek::new([7u8; 32]);
        let aad = compute_wrapped_key_aad(1, 65536, 3, 1, &[0u8; 32]);

        let (ct, nonce) = encrypt_master_key(&mk, &kek, &aad).unwrap();
        assert_eq!(ct.len(), 48);

        let decrypted_mk = decrypt_master_key(&ct, &nonce, &kek, &aad).unwrap();
        assert_eq!(decrypted_mk.as_bytes(), mk.as_bytes());

        let bad_aad = compute_wrapped_key_aad(1, 65536, 3, 1, &[1u8; 32]);
        assert!(decrypt_master_key(&ct, &nonce, &kek, &bad_aad).is_err());

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xff;
        assert!(decrypt_master_key(&bad_ct, &nonce, &kek, &aad).is_err());
    }

    #[test]
    fn test_payload_encrypt_decrypt_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let payload = b"Test secret TOTP accounts json string content 1234567890";
        let aad = compute_payload_aad(1, 1710000000);

        let (ct, nonce) = encrypt_payload(payload, &mk, &aad).unwrap();
        assert_eq!(ct.len(), payload.len() + 16);

        let decrypted = decrypt_payload(&ct, &nonce, &mk, &aad).unwrap();
        assert_eq!(decrypted.as_slice(), payload);

        let bad_aad = compute_payload_aad(1, 1710000001);
        assert!(decrypt_payload(&ct, &nonce, &mk, &bad_aad).is_err());
    }

    #[test]
    fn test_aad_construction_byte_exactness() {
        let salt = [0x53u8; 32];
        let aad_mk = compute_wrapped_key_aad(1, 65536, 3, 1, &salt);
        assert!(aad_mk.starts_with(b"AUTHDESK_MK_V1:"));
        assert_eq!(aad_mk.len(), 15 + 16 + 32);

        let aad_payload = compute_payload_aad(1, 1710000000);
        assert!(aad_payload.starts_with(b"AUTHDESK_PAYLOAD_V1:"));
        assert_eq!(aad_payload.len(), 20 + 4 + 8);
    }

    #[test]
    fn test_fractional_block_padding_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let _kek = DerivedKek::new([42u8; 32]);

        for len in [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let aad = compute_payload_aad(1, 1710000000 + len as i64);

            let (ct, nonce) = encrypt_payload(&payload, &mk, &aad).unwrap();
            assert_eq!(ct.len(), len + 16);

            let pt = decrypt_payload(&ct, &nonce, &mk, &aad).unwrap();
            assert_eq!(pt, payload);
        }
    }
}
