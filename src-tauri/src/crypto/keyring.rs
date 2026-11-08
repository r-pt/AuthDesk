// [ENC-B64::cnB0|Z2Ft|cm9k]
use data_encoding::BASE64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead::MasterKey;
use crate::error::AuthDeskError;

pub const KEYRING_SERVICE: &str = "authdesk";
pub const KEYRING_DEVICE_KEY: &str = "device-key";
pub const KEYRING_PIN_BLOB: &str = "pin-blob";
pub const KEYRING_PASSWORDLESS_MK: &str = "passwordless-mk";
pub const PASSWORDLESS_INTERNAL_KEY: &str = "AUTHDESK_PASSWORDLESS_INTERNAL_KEY_V1";
pub const PIN_AAD: &[u8] = b"AUTHDESK_PIN_MK_V1";

static TEST_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinBlob {
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub struct DeviceKey {
    pub(crate) key: [u8; 32],
}

impl DeviceKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Clone for DeviceKey {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Zeroize for DeviceKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DeviceKey {}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKey([REDACTED])")
    }
}

pub fn enable_test_keyring() {
    TEST_MODE.store(true, Ordering::SeqCst);
    let _ = keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
}

pub fn is_keyring_available() -> bool {
    KeyringStorage::new().is_available()
}

pub fn get_or_create_device_key() -> Result<DeviceKey, AuthDeskError> {
    KeyringStorage::new().get_or_create_device_key()
}

pub fn get_device_key() -> Result<Option<DeviceKey>, AuthDeskError> {
    KeyringStorage::new().get_device_key()
}

pub fn set_device_key(dk: &DeviceKey) -> Result<(), AuthDeskError> {
    KeyringStorage::new().set_device_key(dk)
}

pub fn get_pin_blob() -> Result<Option<PinBlob>, AuthDeskError> {
    KeyringStorage::new().get_pin_blob()
}

pub fn set_pin_blob(blob: &PinBlob) -> Result<(), AuthDeskError> {
    KeyringStorage::new().set_pin_blob(blob)
}

pub fn delete_pin_blob() -> Result<(), AuthDeskError> {
    KeyringStorage::new().delete_pin_blob()
}

pub fn delete_device_key() -> Result<(), AuthDeskError> {
    KeyringStorage::new().delete_device_key()
}

pub fn get_passwordless_mk() -> Result<Option<MasterKey>, AuthDeskError> {
    KeyringStorage::new().get_passwordless_mk()
}

pub fn set_passwordless_mk(mk: &MasterKey) -> Result<(), AuthDeskError> {
    KeyringStorage::new().set_passwordless_mk(mk)
}

pub fn delete_passwordless_mk() -> Result<(), AuthDeskError> {
    KeyringStorage::new().delete_passwordless_mk()
}

pub fn clear_keyring() -> Result<(), AuthDeskError> {
    KeyringStorage::new().clear()
}

#[derive(Debug, Clone)]
pub struct KeyringStorage {
    mock_store: Option<Arc<RwLock<HashMap<String, String>>>>,
    force_unavailable: Arc<AtomicBool>,
}

impl Default for KeyringStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringStorage {
    pub fn new() -> Self {
        if TEST_MODE.load(Ordering::SeqCst) {
            Self::new_in_memory()
        } else {
            Self {
                mock_store: None,
                force_unavailable: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            mock_store: Some(Arc::new(RwLock::new(HashMap::new()))),
            force_unavailable: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn force_unavailable(&self, unavailable: bool) {
        self.force_unavailable.store(unavailable, Ordering::SeqCst);
    }

    pub fn is_available(&self) -> bool {
        if self.force_unavailable.load(Ordering::SeqCst) {
            return false;
        }
        if self.mock_store.is_some() {
            return true;
        }
        match keyring::Entry::new(KEYRING_SERVICE, "probe").and_then(|e| e.get_secret()) {
            Ok(_) => true,
            Err(keyring::Error::NoEntry) => true,
            Err(_) => false,
        }
    }

    fn get_raw(&self, key: &str) -> Result<Option<String>, AuthDeskError> {
        if self.force_unavailable.load(Ordering::SeqCst) {
            return Err(AuthDeskError::Vault("Keyring unavailable".to_string()));
        }
        if let Some(store) = &self.mock_store {
            let map = store.read().unwrap();
            return Ok(map.get(key).cloned());
        }
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| AuthDeskError::Vault(format!("Keyring error: {}", e)))?;
        match entry.get_password() {
            Ok(pass) => Ok(Some(pass)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AuthDeskError::Vault(format!("Keyring get error: {}", e))),
        }
    }

    fn set_raw(&self, key: &str, val: &str) -> Result<(), AuthDeskError> {
        if self.force_unavailable.load(Ordering::SeqCst) {
            return Err(AuthDeskError::Vault("Keyring unavailable".to_string()));
        }
        if let Some(store) = &self.mock_store {
            let mut map = store.write().unwrap();
            map.insert(key.to_string(), val.to_string());
            return Ok(());
        }
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| AuthDeskError::Vault(format!("Keyring error: {}", e)))?;
        entry
            .set_password(val)
            .map_err(|e| AuthDeskError::Vault(format!("Keyring set error: {}", e)))?;
        Ok(())
    }

    fn delete_raw(&self, key: &str) -> Result<(), AuthDeskError> {
        if self.force_unavailable.load(Ordering::SeqCst) {
            return Err(AuthDeskError::Vault("Keyring unavailable".to_string()));
        }
        if let Some(store) = &self.mock_store {
            let mut map = store.write().unwrap();
            map.remove(key);
            return Ok(());
        }
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| AuthDeskError::Vault(format!("Keyring error: {}", e)))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(AuthDeskError::Vault(format!("Keyring delete error: {}", e))),
        }
    }

    pub fn get_or_create_device_key(&self) -> Result<DeviceKey, AuthDeskError> {
        if let Some(existing) = self.get_device_key()? {
            return Ok(existing);
        }
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let dk = DeviceKey::new(key_bytes);
        self.set_device_key(&dk)?;
        Ok(dk)
    }

    pub fn get_device_key(&self) -> Result<Option<DeviceKey>, AuthDeskError> {
        match self.get_raw(KEYRING_DEVICE_KEY)? {
            Some(b64) => {
                let bytes = BASE64
                    .decode(b64.as_bytes())
                    .map_err(|e| AuthDeskError::Vault(format!("Invalid device key base64: {}", e)))?;
                if bytes.len() != 32 {
                    return Err(AuthDeskError::Vault("Device key invalid length".to_string()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(DeviceKey::new(key)))
            }
            None => Ok(None),
        }
    }

    pub fn set_device_key(&self, dk: &DeviceKey) -> Result<(), AuthDeskError> {
        let b64 = BASE64.encode(dk.as_bytes());
        self.set_raw(KEYRING_DEVICE_KEY, &b64)
    }

    pub fn get_pin_blob(&self) -> Result<Option<PinBlob>, AuthDeskError> {
        match self.get_raw(KEYRING_PIN_BLOB)? {
            Some(json) => {
                let blob: PinBlob = serde_json::from_str(&json)
                    .map_err(|e| AuthDeskError::Vault(format!("Invalid pin blob json: {}", e)))?;
                Ok(Some(blob))
            }
            None => Ok(None),
        }
    }

    pub fn set_pin_blob(&self, blob: &PinBlob) -> Result<(), AuthDeskError> {
        let json = serde_json::to_string(blob)
            .map_err(|e| AuthDeskError::Vault(format!("Failed to serialize pin blob: {}", e)))?;
        self.set_raw(KEYRING_PIN_BLOB, &json)
    }

    pub fn delete_pin_blob(&self) -> Result<(), AuthDeskError> {
        self.delete_raw(KEYRING_PIN_BLOB)
    }

    pub fn delete_device_key(&self) -> Result<(), AuthDeskError> {
        self.delete_raw(KEYRING_DEVICE_KEY)
    }

    pub fn get_passwordless_mk(&self) -> Result<Option<MasterKey>, AuthDeskError> {
        match self.get_raw(KEYRING_PASSWORDLESS_MK)? {
            Some(b64) => {
                let bytes = BASE64
                    .decode(b64.as_bytes())
                    .map_err(|e| AuthDeskError::Vault(format!("Invalid passwordless MK base64: {}", e)))?;
                if bytes.len() != 32 {
                    return Err(AuthDeskError::Vault("Passwordless MK invalid length".to_string()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(MasterKey::new(key)))
            }
            None => Ok(None),
        }
    }

    pub fn set_passwordless_mk(&self, mk: &MasterKey) -> Result<(), AuthDeskError> {
        let b64 = BASE64.encode(mk.as_bytes());
        self.set_raw(KEYRING_PASSWORDLESS_MK, &b64)
    }

    pub fn delete_passwordless_mk(&self) -> Result<(), AuthDeskError> {
        self.delete_raw(KEYRING_PASSWORDLESS_MK)
    }

    pub fn clear(&self) -> Result<(), AuthDeskError> {
        self.delete_raw(KEYRING_PIN_BLOB)?;
        self.delete_raw(KEYRING_DEVICE_KEY)?;
        self.delete_raw(KEYRING_PASSWORDLESS_MK)?;
        Ok(())
    }
}
