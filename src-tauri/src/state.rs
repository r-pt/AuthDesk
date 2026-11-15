// [ENC-B64::cnB0|Z2Ft|cm9k]
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use data_encoding::BASE64;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{
    compute_payload_aad, compute_wrapped_key_aad, decrypt_master_key, decrypt_payload,
    encrypt_master_key, encrypt_payload, generate_master_key, MasterKey,
};
use crate::crypto::kdf::{derive_kek, derive_pin_kek, generate_salt, Argon2Params};
use crate::crypto::keyring::{
    KeyringStorage, PinBlob, PASSWORDLESS_INTERNAL_KEY, PIN_AAD,
};
use crate::error::AuthDeskError;
use crate::models::{
    normalize_window_mode, Account, AccountCodeDto, AccountSummaryDto, AccountType, AddAccountDto,
    Algorithm, ExportQrResultDto, ImportConfirmResultDto, ImportPreviewItemDto,
    ImportPreviewResultDto, QrImageInputDto, UpdateAccountDto, VaultStatusDto, WindowSettingsDto,
};
use crate::otp::migration::{
    encode_export_qr_batches, parse_import_qr_images, parse_import_uris, ParsedImportBatch,
};
use crate::otp::totp::{calculate_remaining_seconds, generate_totp};
use crate::storage::atomic::{atomic_write_file, default_vault_path, safe_read_file};
use crate::storage::vault_file::{
    EncryptedBlob, KdfConfig, VaultEnvelope, VaultPayload, KDF_ALGO_ARGON2ID, VAULT_MAGIC,
    VAULT_VERSION,
};

// [ENC-B64::cnB0|Z2Ft|cm9k]
fn is_duplicate_account(
    accounts: &[Account],
    candidate_id: Option<&str>,
    candidate_issuer: &str,
    candidate_account: &str,
    candidate_norm_secret: &str,
) -> bool {
    let norm_iss = candidate_issuer.trim().to_lowercase();
    let norm_acc = candidate_account.trim().to_lowercase();

    for a in accounts {
        if let Some(cand_id) = candidate_id {
            if a.id == cand_id {
                continue;
            }
        }
        if a.issuer.trim().to_lowercase() == norm_iss
            && a.account.trim().to_lowercase() == norm_acc
        {
            if let Ok(existing_norm) = crate::otp::base32::normalize_base32(&a.secret) {
                if existing_norm == candidate_norm_secret {
                    return true;
                }
            }
        }
    }
    false
}

fn check_duplicate_account(
    accounts: &[Account],
    candidate_id: Option<&str>,
    candidate_issuer: &str,
    candidate_account: &str,
    candidate_norm_secret: &str,
) -> Result<(), AuthDeskError> {
    if is_duplicate_account(
        accounts,
        candidate_id,
        candidate_issuer,
        candidate_account,
        candidate_norm_secret,
    ) {
        return Err(AuthDeskError::DuplicateAccount(
            "Ya existe una cuenta con el mismo emisor, cuenta y clave secreta".to_string(),
        ));
    }
    Ok(())
}

fn unwrap_envelope_master_key(
    env: &VaultEnvelope,
    secret_key: &str,
) -> Result<MasterKey, AuthDeskError> {
    let salt = BASE64
        .decode(env.kdf.salt_b64.as_bytes())
        .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    let params = Argon2Params {
        m_cost_kib: env.kdf.m_cost_kib,
        t_cost: env.kdf.t_cost,
        p_cost: env.kdf.p_cost,
    };
    let kek = derive_kek(secret_key, &salt, &params)?;
    let mk_aad = compute_wrapped_key_aad(
        env.version,
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        &salt,
    );
    let mk_nonce_bytes = BASE64
        .decode(env.wrapped_master_key.nonce_b64.as_bytes())
        .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    let mk_nonce: [u8; 24] = mk_nonce_bytes
        .try_into()
        .map_err(|_| AuthDeskError::Vault("Invalid wrapped MK nonce length".to_string()))?;
    let mk_ct = BASE64
        .decode(env.wrapped_master_key.ciphertext_b64.as_bytes())
        .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    decrypt_master_key(&mk_ct, &mk_nonce, &kek, &mk_aad)
}

fn wrap_envelope_master_key(
    version: u32,
    kek_secret: &str,
    mk: &MasterKey,
) -> Result<(KdfConfig, EncryptedBlob), AuthDeskError> {
    let salt = generate_salt();
    let params = Argon2Params::default();
    let kek = derive_kek(kek_secret, &salt, &params)?;
    let mk_aad = compute_wrapped_key_aad(
        version,
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        &salt,
    );
    let (mk_ct, mk_nonce) = encrypt_master_key(mk, &kek, &mk_aad)?;
    Ok((
        KdfConfig {
            algorithm: KDF_ALGO_ARGON2ID.to_string(),
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt_b64: BASE64.encode(&salt),
        },
        EncryptedBlob {
            nonce_b64: BASE64.encode(&mk_nonce),
            ciphertext_b64: BASE64.encode(&mk_ct),
        },
    ))
}

fn decrypt_envelope_payload(
    env: &VaultEnvelope,
    mk: &MasterKey,
) -> Result<VaultPayload, AuthDeskError> {
    let payload_aad = compute_payload_aad(env.version, env.updated_at);
    let p_nonce_bytes = BASE64
        .decode(env.payload.nonce_b64.as_bytes())
        .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    let p_nonce: [u8; 24] = p_nonce_bytes
        .try_into()
        .map_err(|_| AuthDeskError::Vault("Invalid payload nonce length".to_string()))?;
    let p_ct = BASE64
        .decode(env.payload.ciphertext_b64.as_bytes())
        .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    let mut pt = decrypt_payload(&p_ct, &p_nonce, mk, &payload_aad)?;
    let payload_result: Result<VaultPayload, _> = serde_json::from_slice(&pt);
    pt.zeroize();
    payload_result.map_err(|e| AuthDeskError::Vault(e.to_string()))
}

fn encrypt_envelope_payload(
    version: u32,
    updated_at: i64,
    payload_obj: &VaultPayload,
    mk: &MasterKey,
) -> Result<EncryptedBlob, AuthDeskError> {
    let mut payload_bytes =
        serde_json::to_vec(payload_obj).map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    let payload_aad = compute_payload_aad(version, updated_at);
    let enc_res = encrypt_payload(&payload_bytes, mk, &payload_aad);
    payload_bytes.zeroize();
    let (payload_ct, payload_nonce) = enc_res?;
    Ok(EncryptedBlob {
        nonce_b64: BASE64.encode(&payload_nonce),
        ciphertext_b64: BASE64.encode(&payload_ct),
    })
}

pub struct AppState {
    pub vault_path: PathBuf,
    pub accounts: RwLock<Vec<Account>>,
    pub staged_import: RwLock<Vec<Account>>,
    pub master_key: RwLock<Option<MasterKey>>,
    pub pin_failed_attempts: AtomicU32,
    pub keyring: KeyringStorage,
    pub window_settings: RwLock<WindowSettingsDto>,
    pub last_window_op_ms: AtomicU64,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let vault_path = default_vault_path();
        Self::with_path(vault_path)
    }

    pub fn with_accounts(accounts: Vec<Account>) -> Self {
        Self {
            vault_path: std::env::temp_dir().join(format!(
                "authdesk_mem_accounts_{}_{}.enc",
                std::process::id(),
                rand::random::<u64>()
            )),
            accounts: RwLock::new(accounts),
            staged_import: RwLock::new(Vec::new()),
            master_key: RwLock::new(Some(MasterKey::new([0u8; 32]))),
            pin_failed_attempts: AtomicU32::new(0),
            keyring: KeyringStorage::new(),
            window_settings: RwLock::new(WindowSettingsDto::default()),
            last_window_op_ms: AtomicU64::new(0),
        }
    }

    pub fn with_path(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            accounts: RwLock::new(Vec::new()),
            staged_import: RwLock::new(Vec::new()),
            master_key: RwLock::new(None),
            pin_failed_attempts: AtomicU32::new(0),
            keyring: KeyringStorage::new(),
            window_settings: RwLock::new(WindowSettingsDto::default()),
            last_window_op_ms: AtomicU64::new(0),
        }
    }



    pub fn default_test_accounts() -> Vec<Account> {
        vec![
            Account {
                id: "test-github-1".to_string(),
                issuer: "GitHub".to_string(),
                account: "octocat@github.com".to_string(),
                secret: "JBSWY3DPEHPK3PXP".to_string(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                account_type: AccountType::Totp,
                counter: None,
            },
            Account {
                id: "test-google-2".to_string(),
                issuer: "Google".to_string(),
                account: "alex.developer@gmail.com".to_string(),
                secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                account_type: AccountType::Totp,
                counter: None,
            },
            Account {
                id: "test-aws-3".to_string(),
                issuer: "Amazon Web Services".to_string(),
                account: "root-account".to_string(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                account_type: AccountType::Totp,
                counter: None,
            },
            Account {
                id: "test-proton-4".to_string(),
                issuer: "Proton".to_string(),
                account: "security@proton.me".to_string(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====".to_string(),
                algorithm: Algorithm::Sha256,
                digits: 8,
                period: 30,
                account_type: AccountType::Totp,
                counter: None,
            },
            Account {
                id: "test-cloudflare-5".to_string(),
                issuer: "Cloudflare".to_string(),
                account: "admin@infra.corp".to_string(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=".to_string(),
                algorithm: Algorithm::Sha512,
                digits: 8,
                period: 60,
                account_type: AccountType::Totp,
                counter: None,
            },
        ]
    }

    pub fn is_locked(&self) -> bool {
        self.master_key.read().map(|mk| mk.is_none()).unwrap_or(true)
    }

    pub fn is_passwordless(&self) -> bool {
        if !self.vault_path.exists() {
            return false;
        }
        if let Ok(bytes) = safe_read_file(&self.vault_path) {
            serde_json::from_slice::<VaultEnvelope>(&bytes)
                .map(|e| e.passwordless)
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub fn is_pin_enabled(&self) -> bool {
        self.keyring.is_available()
            && self.vault_path.exists()
            && self.keyring.get_pin_blob().map(|b| b.is_some()).unwrap_or(false)
    }

    pub fn can_lock_vault(&self) -> bool {
        self.vault_path.exists() && (!self.is_passwordless() || self.is_pin_enabled())
    }

    pub fn get_vault_status(&self) -> VaultStatusDto {
        let initialized = self.vault_path.exists();
        let is_pwless = self.is_passwordless();
        let pin_available = self.keyring.is_available();
        let pin_enabled = self.is_pin_enabled();

        if initialized
            && is_pwless
            && !pin_enabled
            && self.is_locked()
            && self.pin_failed_attempts.load(Ordering::SeqCst) == 0
        {
            let _ = self.auto_unlock_if_passwordless();
        }

        let locked = self.is_locked();
        let account_count = if locked {
            0
        } else {
            self.accounts.read().map(|a| a.len()).unwrap_or(0)
        };
        let pin_attempts_remaining = if pin_enabled {
            let failed = self.pin_failed_attempts.load(Ordering::SeqCst);
            Some(5u32.saturating_sub(failed))
        } else {
            None
        };
        VaultStatusDto {
            initialized,
            locked,
            account_count,
            pin_available,
            pin_enabled,
            pin_attempts_remaining,
            passwordless: is_pwless,
        }
    }

    pub fn mark_window_op(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_window_op_ms.store(now_ms, Ordering::SeqCst);
    }

    pub fn is_recent_window_op(&self, threshold_ms: u64) -> bool {
        let last = self.last_window_op_ms.load(Ordering::SeqCst);
        if last == 0 {
            return false;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms.saturating_sub(last) <= threshold_ms
    }

    pub fn get_window_settings(&self) -> WindowSettingsDto {
        self.window_settings
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn set_window_settings(&self, mut settings: WindowSettingsDto) {
        if let Ok(norm) = normalize_window_mode(&settings.mode) {
            settings.mode = norm.to_string();
        } else {
            settings.mode = "popup".to_string();
        }
        if let Ok(mut lock) = self.window_settings.write() {
            *lock = settings;
        }
    }

    pub fn set_window_mode(&self, mode: &str) -> Result<(), AuthDeskError> {
        let normalized = normalize_window_mode(mode)?;
        if let Ok(mut lock) = self.window_settings.write() {
            lock.mode = normalized.to_string();
            Ok(())
        } else {
            Err(AuthDeskError::Vault(
                "Failed to acquire window settings lock".to_string(),
            ))
        }
    }

    pub fn set_popup_position(&self, pos: &str) -> Result<(), AuthDeskError> {
        if let Ok(mut lock) = self.window_settings.write() {
            lock.popup_position = pos.to_string();
            Ok(())
        } else {
            Err(AuthDeskError::Vault(
                "Failed to acquire window settings lock".to_string(),
            ))
        }
    }

    pub fn set_always_on_top(&self, enabled: bool) -> Result<(), AuthDeskError> {
        if let Ok(mut lock) = self.window_settings.write() {
            lock.always_on_top = enabled;
            Ok(())
        } else {
            Err(AuthDeskError::Vault(
                "Failed to acquire window settings lock".to_string(),
            ))
        }
    }

    pub fn set_auto_hide_on_blur(&self, enabled: bool) -> Result<(), AuthDeskError> {
        if let Ok(mut lock) = self.window_settings.write() {
            lock.auto_hide_on_blur = enabled;
            Ok(())
        } else {
            Err(AuthDeskError::Vault(
                "Failed to acquire window settings lock".to_string(),
            ))
        }
    }

    pub fn set_window_resizable(&self, resizable: bool) -> Result<(), AuthDeskError> {
        if let Ok(mut lock) = self.window_settings.write() {
            lock.resizable = resizable;
            Ok(())
        } else {
            Err(AuthDeskError::Vault(
                "Failed to acquire window settings lock".to_string(),
            ))
        }
    }

    pub fn init_vault_passwordless(&self) -> Result<(), AuthDeskError> {
        let mk = generate_master_key();
        let salt = generate_salt();
        let params = Argon2Params::default();
        let kek = derive_kek(PASSWORDLESS_INTERNAL_KEY, &salt, &params)?;

        let mk_aad = compute_wrapped_key_aad(
            VAULT_VERSION,
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            &salt,
        );
        let (mk_ct, mk_nonce) = encrypt_master_key(&mk, &kek, &mk_aad)?;

        let _ = self.keyring.set_passwordless_mk(&mk);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let accounts = self.accounts.read()?.clone();
        let payload_obj = VaultPayload {
            version: VAULT_VERSION,
            accounts,
        };
        let mut payload_bytes = serde_json::to_vec(&payload_obj)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let payload_aad = compute_payload_aad(VAULT_VERSION, now);
        let (payload_ct, payload_nonce) = encrypt_payload(&payload_bytes, &mk, &payload_aad)?;
        payload_bytes.zeroize();

        let env = VaultEnvelope {
            magic: VAULT_MAGIC.to_string(),
            version: VAULT_VERSION,
            created_at: now,
            updated_at: now,
            kdf: KdfConfig {
                algorithm: KDF_ALGO_ARGON2ID.to_string(),
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt_b64: BASE64.encode(&salt),
            },
            wrapped_master_key: EncryptedBlob {
                nonce_b64: BASE64.encode(&mk_nonce),
                ciphertext_b64: BASE64.encode(&mk_ct),
            },
            payload: EncryptedBlob {
                nonce_b64: BASE64.encode(&payload_nonce),
                ciphertext_b64: BASE64.encode(&payload_ct),
            },
            passwordless: true,
        };

        env.validate()?;
        let json = serde_json::to_vec_pretty(&env)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        atomic_write_file(&self.vault_path, &json)?;

        *self.master_key.write()? = Some(mk);
        Ok(())
    }

    pub fn auto_unlock_if_passwordless(&self) -> Result<bool, AuthDeskError> {
        if !self.vault_path.exists() {
            return Ok(false);
        }
        if self.is_pin_enabled() || self.pin_failed_attempts.load(Ordering::SeqCst) > 0 {
            return Ok(false);
        }
        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        if !env.passwordless {
            return Ok(false);
        }

        if !self.is_locked() {
            return Ok(true);
        }

        let payload_aad = compute_payload_aad(env.version, env.updated_at);
        let p_nonce_bytes = BASE64
            .decode(env.payload.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let p_nonce: [u8; 24] = p_nonce_bytes
            .try_into()
            .map_err(|_| AuthDeskError::Vault("Invalid payload nonce length".to_string()))?;
        let p_ct = BASE64
            .decode(env.payload.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        let mut recovered_mk: Option<MasterKey> = None;

        if self.keyring.is_available() {
            if let Ok(Some(keyring_mk)) = self.keyring.get_passwordless_mk() {
                if let Ok(mut pt) = decrypt_payload(&p_ct, &p_nonce, &keyring_mk, &payload_aad) {
                    if let Ok(payload) = serde_json::from_slice::<VaultPayload>(&pt) {
                        pt.zeroize();
                        *self.accounts.write()? = payload.accounts;
                        recovered_mk = Some(keyring_mk);
                    } else {
                        pt.zeroize();
                    }
                }
            }
        }

        if recovered_mk.is_none() {
            let salt = BASE64
                .decode(env.kdf.salt_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
            let params = Argon2Params {
                m_cost_kib: env.kdf.m_cost_kib,
                t_cost: env.kdf.t_cost,
                p_cost: env.kdf.p_cost,
            };
            let kek = derive_kek(PASSWORDLESS_INTERNAL_KEY, &salt, &params)?;
            let mk_aad = compute_wrapped_key_aad(
                env.version,
                params.m_cost_kib,
                params.t_cost,
                params.p_cost,
                &salt,
            );
            let mk_nonce_bytes = BASE64
                .decode(env.wrapped_master_key.nonce_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
            let mk_nonce: [u8; 24] = mk_nonce_bytes
                .try_into()
                .map_err(|_| AuthDeskError::Vault("Invalid wrapped MK nonce length".to_string()))?;
            let mk_ct = BASE64
                .decode(env.wrapped_master_key.ciphertext_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
            let fallback_mk = decrypt_master_key(&mk_ct, &mk_nonce, &kek, &mk_aad)?;

            let mut pt = decrypt_payload(&p_ct, &p_nonce, &fallback_mk, &payload_aad)?;
            let payload_result: Result<VaultPayload, _> = serde_json::from_slice(&pt);
            pt.zeroize();
            let payload = payload_result.map_err(|e| AuthDeskError::Vault(e.to_string()))?;

            if self.keyring.is_available() {
                let _ = self.keyring.set_passwordless_mk(&fallback_mk);
            }
            *self.accounts.write()? = payload.accounts;
            recovered_mk = Some(fallback_mk);
        }

        if let Some(mk) = recovered_mk {
            *self.master_key.write()? = Some(mk);
            Ok(true)
        } else {
            Err(AuthDeskError::Vault(
                "No se pudo desbloquear la bóveda sin contraseña".to_string(),
            ))
        }
    }

    pub fn set_master_password(
        &self,
        current_password: Option<&str>,
        new_password: &str,
    ) -> Result<(), AuthDeskError> {
        if new_password.trim().len() < 8 {
            return Err(AuthDeskError::Vault(
                "La contraseña debe tener al menos 8 caracteres".to_string(),
            ));
        }

        if !self.vault_path.exists() {
            return self.init_vault(new_password);
        }

        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        let old_mk = if env.passwordless {
            if let Some(existing_mk) = self.master_key.read()?.as_ref() {
                existing_mk.clone()
            } else {
                unwrap_envelope_master_key(&env, PASSWORDLESS_INTERNAL_KEY)?
            }
        } else {
            let cur_pwd = current_password.ok_or_else(|| {
                AuthDeskError::Vault("Se requiere la contraseña actual".to_string())
            })?;
            unwrap_envelope_master_key(&env, cur_pwd)?
        };

        let payload_obj = decrypt_envelope_payload(&env, &old_mk)?;
        let mk = if !self.is_pin_enabled() {
            drop(old_mk);
            generate_master_key()
        } else {
            old_mk
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let new_payload_blob = encrypt_envelope_payload(env.version, now, &payload_obj, &mk)?;
        let (kdf, wrapped_master_key) =
            wrap_envelope_master_key(env.version, new_password, &mk)?;

        let updated_env = VaultEnvelope {
            magic: env.magic,
            version: env.version,
            created_at: env.created_at,
            updated_at: now,
            kdf,
            wrapped_master_key,
            payload: new_payload_blob,
            passwordless: false,
        };

        updated_env.validate()?;
        let json = serde_json::to_vec_pretty(&updated_env)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        atomic_write_file(&self.vault_path, &json)?;
        atomic_write_file(&self.vault_path, &json)?;

        let _ = self.keyring.delete_passwordless_mk();
        *self.accounts.write()? = payload_obj.accounts;
        *self.master_key.write()? = Some(mk);
        Ok(())
    }

    pub fn remove_master_password(&self, current_password: &str) -> Result<(), AuthDeskError> {
        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        if env.passwordless {
            return Ok(());
        }

        let old_mk = unwrap_envelope_master_key(&env, current_password)?;
        let payload_obj = decrypt_envelope_payload(&env, &old_mk)?;
        drop(old_mk);
        let mk = generate_master_key();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let new_payload_blob = encrypt_envelope_payload(env.version, now, &payload_obj, &mk)?;
        let (kdf, wrapped_master_key) =
            wrap_envelope_master_key(env.version, PASSWORDLESS_INTERNAL_KEY, &mk)?;

        let updated_env = VaultEnvelope {
            magic: env.magic,
            version: env.version,
            created_at: env.created_at,
            updated_at: now,
            kdf,
            wrapped_master_key,
            payload: new_payload_blob,
            passwordless: true,
        };

        updated_env.validate()?;
        let json = serde_json::to_vec_pretty(&updated_env)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        atomic_write_file(&self.vault_path, &json)?;
        atomic_write_file(&self.vault_path, &json)?;

        *self.accounts.write()? = payload_obj.accounts;
        *self.master_key.write()? = Some(mk.clone());
        let _ = self.disable_pin();
        let _ = self.keyring.set_passwordless_mk(&mk);
        Ok(())
    }

    pub fn change_master_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthDeskError> {
        self.set_master_password(Some(current_password), new_password)
    }

    pub fn load_demo_accounts(&self) -> Result<usize, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }

        let demo_specs = [
            (
                "GitHub",
                "demo@github.com",
                "JBSWY3DPEHPK3PXP",
                Algorithm::Sha1,
                6,
                30,
            ),
            (
                "Google",
                "demo@gmail.com",
                "KRSXG5CTMVRXEZLU",
                Algorithm::Sha1,
                6,
                30,
            ),
            (
                "AWS",
                "admin@company.aws",
                "MZXW633PN5XW6MZX",
                Algorithm::Sha1,
                6,
                30,
            ),
            (
                "Proton",
                "user@proton.me",
                "NBSWY3DPEHPK3PXP",
                Algorithm::Sha1,
                6,
                30,
            ),
            (
                "Cloudflare",
                "ops@cloudflare.com",
                "OBZXE43VMVRXEZLU",
                Algorithm::Sha1,
                6,
                30,
            ),
        ];

        let mut accounts = self.accounts.write()?;
        let mut added_count = 0;

        for (issuer, account, secret, algo, digits, period) in demo_specs {
            let norm_iss = issuer.trim().to_lowercase();
            let norm_acc = account.trim().to_lowercase();
            let exists = accounts.iter().any(|a| {
                a.issuer.trim().to_lowercase() == norm_iss
                    && a.account.trim().to_lowercase() == norm_acc
            });

            if !exists {
                let id = format!("demo_{}_{}", norm_iss, rand::random::<u32>());
                let acc = Account::new(
                    id,
                    issuer.to_string(),
                    account.to_string(),
                    secret.to_string(),
                    algo,
                    digits,
                    period,
                    AccountType::Totp,
                    None,
                )?;
                accounts.push(acc);
                added_count += 1;
            }
        }

        drop(accounts);
        if added_count > 0 {
            self.persist_accounts_if_vault_exists()?;
        }
        Ok(added_count)
    }

    pub fn remove_demo_accounts(&self) -> Result<usize, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }

        let demo_keys = [
            ("github", "demo@github.com"),
            ("google", "demo@gmail.com"),
            ("aws", "admin@company.aws"),
            ("proton", "user@proton.me"),
            ("cloudflare", "ops@cloudflare.com"),
        ];

        let mut accounts = self.accounts.write()?;
        let initial_len = accounts.len();

        accounts.retain(|a| {
            let iss = a.issuer.trim().to_lowercase();
            let acc = a.account.trim().to_lowercase();
            !demo_keys
                .iter()
                .any(|(d_iss, d_acc)| &iss == d_iss && &acc == d_acc)
        });

        let removed_count = initial_len - accounts.len();
        drop(accounts);

        if removed_count > 0 {
            self.persist_accounts_if_vault_exists()?;
        }
        Ok(removed_count)
    }


    pub fn init_vault(&self, password: &str) -> Result<(), AuthDeskError> {
        if password.is_empty() {
            return Err(AuthDeskError::Vault("La contraseña no puede estar vacía".to_string()));
        }

        let mk = generate_master_key();
        let salt = generate_salt();
        let params = Argon2Params::default();
        let kek = derive_kek(password, &salt, &params)?;

        let mk_aad = compute_wrapped_key_aad(
            VAULT_VERSION,
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            &salt,
        );
        let (mk_ct, mk_nonce) = encrypt_master_key(&mk, &kek, &mk_aad)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let accounts = self.accounts.read()?.clone();
        let payload_obj = VaultPayload {
            version: VAULT_VERSION,
            accounts,
        };
        let mut payload_bytes = serde_json::to_vec(&payload_obj)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let payload_aad = compute_payload_aad(VAULT_VERSION, now);
        let (payload_ct, payload_nonce) = encrypt_payload(&payload_bytes, &mk, &payload_aad)?;
        payload_bytes.zeroize();

        let env = VaultEnvelope {
            magic: VAULT_MAGIC.to_string(),
            version: VAULT_VERSION,
            created_at: now,
            updated_at: now,
            kdf: KdfConfig {
                algorithm: KDF_ALGO_ARGON2ID.to_string(),
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt_b64: BASE64.encode(&salt),
            },
            wrapped_master_key: EncryptedBlob {
                nonce_b64: BASE64.encode(&mk_nonce),
                ciphertext_b64: BASE64.encode(&mk_ct),
            },
            payload: EncryptedBlob {
                nonce_b64: BASE64.encode(&payload_nonce),
                ciphertext_b64: BASE64.encode(&payload_ct),
            },
            passwordless: false,
        };

        env.validate()?;
        let json = serde_json::to_vec_pretty(&env)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        atomic_write_file(&self.vault_path, &json)?;

        *self.master_key.write()? = Some(mk);
        Ok(())
    }

    pub fn unlock_vault(&self, password: &str) -> Result<(), AuthDeskError> {
        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        let salt = BASE64
            .decode(env.kdf.salt_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let params = Argon2Params {
            m_cost_kib: env.kdf.m_cost_kib,
            t_cost: env.kdf.t_cost,
            p_cost: env.kdf.p_cost,
        };
        let kek = derive_kek(password, &salt, &params)?;

        let mk_aad = compute_wrapped_key_aad(
            env.version,
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            &salt,
        );
        let mk_nonce_bytes = BASE64
            .decode(env.wrapped_master_key.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let mk_nonce: [u8; 24] = mk_nonce_bytes
            .try_into()
            .map_err(|_| AuthDeskError::Vault("Invalid wrapped MK nonce length".to_string()))?;
        let mk_ct = BASE64
            .decode(env.wrapped_master_key.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let mk = decrypt_master_key(&mk_ct, &mk_nonce, &kek, &mk_aad)?;

        let payload_aad = compute_payload_aad(env.version, env.updated_at);
        let p_nonce_bytes = BASE64
            .decode(env.payload.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let p_nonce: [u8; 24] = p_nonce_bytes
            .try_into()
            .map_err(|_| AuthDeskError::Vault("Invalid payload nonce length".to_string()))?;
        let p_ct = BASE64
            .decode(env.payload.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let mut pt = decrypt_payload(&p_ct, &p_nonce, &mk, &payload_aad)?;

        let payload_result: Result<VaultPayload, _> = serde_json::from_slice(&pt);
        pt.zeroize();
        let payload = payload_result.map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        *self.accounts.write()? = payload.accounts;
        *self.master_key.write()? = Some(mk);
        self.pin_failed_attempts.store(0, Ordering::SeqCst);
        Ok(())
    }

    pub fn set_pin(&self, mut pin: String) -> Result<(), AuthDeskError> {
        if self.is_locked() {
            pin.zeroize();
            return Err(AuthDeskError::Vault(
                "Bóveda bloqueada: debe desbloquear con contraseña maestra para configurar PIN".to_string(),
            ));
        }
        if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
            pin.zeroize();
            return Err(AuthDeskError::Vault(
                "El PIN debe tener exactamente 6 dígitos numéricos".to_string(),
            ));
        }
        if !self.keyring.is_available() {
            pin.zeroize();
            return Err(AuthDeskError::Vault("Keyring del sistema no disponible".to_string()));
        }

        let mk_guard = self.master_key.read()?;
        let mk = match mk_guard.as_ref() {
            Some(k) => k.clone(),
            None => {
                pin.zeroize();
                return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
            }
        };
        drop(mk_guard);

        let device_key = self.keyring.get_or_create_device_key()?;
        let salt = generate_salt();
        let params = Argon2Params::default();
        let mut pin_kek = derive_pin_kek(&pin, &salt, &device_key.key, &params)?;
        pin.zeroize();

        let (ct, nonce) = encrypt_master_key(&mk, &pin_kek, PIN_AAD)?;
        pin_kek.zeroize();

        let blob = PinBlob {
            version: 1,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt_b64: BASE64.encode(&salt),
            nonce_b64: BASE64.encode(&nonce),
            ciphertext_b64: BASE64.encode(&ct),
        };

        self.keyring.set_pin_blob(&blob)?;
        self.pin_failed_attempts.store(0, Ordering::SeqCst);
        Ok(())
    }

    pub fn unlock_with_pin(&self, mut pin: String) -> Result<(), AuthDeskError> {
        let failed = self.pin_failed_attempts.load(Ordering::SeqCst);
        if failed >= 5 {
            pin.zeroize();
            if self.is_passwordless() {
                return Err(AuthDeskError::Vault(
                    "PIN bloqueado por alcanzar 5 intentos fallidos. Reinicie la aplicación para volver a intentar.".to_string(),
                ));
            }
            let _ = self.keyring.delete_pin_blob();
            return Err(AuthDeskError::Vault(
                "PIN bloqueado por demasiados intentos fallidos. Debe desbloquear con contraseña maestra.".to_string(),
            ));
        }

        if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
            pin.zeroize();
            return Err(AuthDeskError::Vault(
                "El PIN debe tener exactamente 6 dígitos numéricos".to_string(),
            ));
        }

        if !self.keyring.is_available() {
            pin.zeroize();
            return Err(AuthDeskError::Vault("Keyring del sistema no disponible".to_string()));
        }

        let device_key = match self.keyring.get_device_key()? {
            Some(k) => k,
            None => {
                pin.zeroize();
                return Err(AuthDeskError::Vault("PIN no configurado".to_string()));
            }
        };

        let blob = match self.keyring.get_pin_blob()? {
            Some(b) => b,
            None => {
                pin.zeroize();
                return Err(AuthDeskError::Vault("PIN no configurado".to_string()));
            }
        };

        let salt = BASE64
            .decode(blob.salt_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let params = Argon2Params {
            m_cost_kib: blob.m_cost_kib,
            t_cost: blob.t_cost,
            p_cost: blob.p_cost,
        };

        let mut pin_kek = match derive_pin_kek(&pin, &salt, &device_key.key, &params) {
            Ok(k) => k,
            Err(e) => {
                pin.zeroize();
                return Err(e);
            }
        };
        pin.zeroize();

        let nonce_bytes = BASE64
            .decode(blob.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let nonce: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| AuthDeskError::Vault("Invalid PIN nonce length".to_string()))?;
        let ct = BASE64
            .decode(blob.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        let mk_res = decrypt_master_key(&ct, &nonce, &pin_kek, PIN_AAD);
        pin_kek.zeroize();

        let mk = match mk_res {
            Ok(k) => {
                self.pin_failed_attempts.store(0, Ordering::SeqCst);
                k
            }
            Err(_) => {
                let new_failed = self.pin_failed_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if new_failed >= 5 {
                    if self.is_passwordless() {
                        return Err(AuthDeskError::Vault(
                            "PIN bloqueado por alcanzar 5 intentos fallidos. Reinicie la aplicación para volver a intentar.".to_string(),
                        ));
                    }
                    let _ = self.keyring.delete_pin_blob();
                    return Err(AuthDeskError::Vault(
                        "PIN bloqueado por alcanzar 5 intentos fallidos. PIN desactivado. Utilice la contraseña maestra.".to_string(),
                    ));
                } else {
                    let remaining = 5 - new_failed;
                    return Err(AuthDeskError::Vault(format!(
                        "PIN incorrecto. Intentos restantes: {}",
                        remaining
                    )));
                }
            }
        };

        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        let payload_aad = compute_payload_aad(env.version, env.updated_at);
        let p_nonce_bytes = BASE64
            .decode(env.payload.nonce_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let p_nonce: [u8; 24] = p_nonce_bytes
            .try_into()
            .map_err(|_| AuthDeskError::Vault("Invalid payload nonce length".to_string()))?;
        let p_ct = BASE64
            .decode(env.payload.ciphertext_b64.as_bytes())
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        let mut pt = decrypt_payload(&p_ct, &p_nonce, &mk, &payload_aad)?;
        let payload_result: Result<VaultPayload, _> = serde_json::from_slice(&pt);
        pt.zeroize();
        let payload = payload_result.map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        *self.accounts.write()? = payload.accounts;
        *self.master_key.write()? = Some(mk);
        Ok(())
    }

    pub fn disable_pin(&self) -> Result<(), AuthDeskError> {
        let _ = self.keyring.delete_pin_blob();
        let _ = self.keyring.delete_device_key();
        self.pin_failed_attempts.store(0, Ordering::SeqCst);
        if self.is_passwordless() {
            if let Ok(guard) = self.master_key.read() {
                if let Some(mk) = guard.as_ref() {
                    let _ = self.keyring.set_passwordless_mk(mk);
                }
            }
        }
        Ok(())
    }

    pub fn lock_vault(&self) -> Result<(), AuthDeskError> {
        if let Some(mut mk) = self.master_key.write()?.take() {
            mk.zeroize();
        }
        let mut accounts = self.accounts.write()?;
        for a in accounts.iter_mut() {
            a.secret.zeroize();
        }
        accounts.clear();
        drop(accounts);
        self.clear_staged_buffer()?;
        Ok(())
    }


    pub fn get_current_codes(&self) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.get_codes_at(now)
    }

    pub fn get_codes_at(&self, timestamp: u64) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let accounts = self.accounts.read()?;
        let mut codes = Vec::with_capacity(accounts.len());

        for acc in accounts.iter() {
            let step = if acc.period == 0 { 30 } else { acc.period };
            let seconds_remaining = calculate_remaining_seconds(timestamp, step);

            let code = generate_totp(
                &acc.secret,
                timestamp,
                acc.algorithm,
                acc.digits,
                step,
            )?;

            codes.push(acc.to_code_dto(code, seconds_remaining));
        }

        Ok(codes)
    }

    pub fn list_account_summaries(&self) -> Result<Vec<AccountSummaryDto>, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let accounts = self.accounts.read()?;
        Ok(accounts.iter().map(|a| a.to_summary_dto()).collect())
    }

    pub fn add_account(&self, account: Account) -> Result<(), AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let norm_secret = crate::otp::base32::normalize_base32(&account.secret)?;
        let mut accounts = self.accounts.write()?;
        check_duplicate_account(&accounts, None, &account.issuer, &account.account, &norm_secret)?;
        accounts.push(account);
        drop(accounts);
        self.persist_accounts_if_vault_exists()?;
        Ok(())
    }

    pub fn add_account_dto(&self, dto: AddAccountDto) -> Result<AccountSummaryDto, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        if dto.issuer.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter("El emisor no puede estar vacío".to_string()));
        }
        if dto.account.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter("La cuenta no puede estar vacía".to_string()));
        }

        let norm_secret = crate::otp::base32::normalize_base32(&dto.secret)?;
        let _ = crate::otp::base32::decode_base32(&norm_secret)?;

        let mut accounts = self.accounts.write()?;
        check_duplicate_account(&accounts, None, &dto.issuer, &dto.account, &norm_secret)?;

        let id = format!("acc_{}_{}", std::process::id(), rand::random::<u64>());
        let acc = Account::new(
            id,
            dto.issuer.trim().to_string(),
            dto.account.trim().to_string(),
            norm_secret,
            dto.algorithm.unwrap_or(Algorithm::Sha1),
            dto.digits.unwrap_or(6),
            dto.period.unwrap_or(30),
            AccountType::Totp,
            None,
        )?;
        let summary = acc.to_summary_dto();
        accounts.push(acc);
        drop(accounts);

        self.persist_accounts_if_vault_exists()?;
        Ok(summary)
    }

    pub fn update_account_dto(&self, dto: UpdateAccountDto) -> Result<AccountSummaryDto, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        if dto.id.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter("ID de cuenta inválido".to_string()));
        }
        if dto.issuer.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter("El emisor no puede estar vacío".to_string()));
        }
        if dto.account.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter("La cuenta no puede estar vacía".to_string()));
        }
        if let Some(d) = dto.digits {
            if d != 6 && d != 8 {
                return Err(AuthDeskError::InvalidParameter("Los dígitos deben ser 6 u 8".to_string()));
            }
        }
        if let Some(p) = dto.period {
            if p == 0 {
                return Err(AuthDeskError::InvalidParameter("El período debe ser mayor a 0".to_string()));
            }
        }

        let mut accounts = self.accounts.write()?;
        let idx = accounts
            .iter()
            .position(|a| a.id == dto.id)
            .ok_or_else(|| AuthDeskError::AccountNotFound(format!("Cuenta {} no encontrada", dto.id)))?;

        let (mut effective_secret, is_new_secret) = match dto.secret {
            Some(ref s) if !s.trim().is_empty() => {
                let norm = crate::otp::base32::normalize_base32(s)?;
                let _ = crate::otp::base32::decode_base32(&norm)?;
                (norm, true)
            }
            _ => (accounts[idx].secret.clone(), false),
        };

        check_duplicate_account(
            &accounts,
            Some(&dto.id),
            &dto.issuer,
            &dto.account,
            &effective_secret,
        )?;

        let acc = &mut accounts[idx];
        acc.issuer = dto.issuer.trim().to_string();
        acc.account = dto.account.trim().to_string();
        if let Some(algo) = dto.algorithm {
            acc.algorithm = algo;
        }
        if let Some(digits) = dto.digits {
            acc.digits = digits;
        }
        if let Some(period) = dto.period {
            acc.period = period;
        }
        if is_new_secret {
            acc.secret.zeroize();
            acc.secret = effective_secret;
        } else {
            effective_secret.zeroize();
        }

        let summary = acc.to_summary_dto();
        drop(accounts);

        self.persist_accounts_if_vault_exists()?;
        Ok(summary)
    }

    pub fn delete_account(&self, id: &str) -> Result<bool, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let mut accounts = self.accounts.write()?;
        if let Some(idx) = accounts.iter().position(|a| a.id == id) {
            accounts[idx].secret.zeroize();
            accounts.remove(idx);
            drop(accounts);
            self.persist_accounts_if_vault_exists()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn reorder_accounts(&self, account_ids: Vec<String>) -> Result<(), AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let mut accounts = self.accounts.write()?;
        if account_ids.len() != accounts.len() {
            return Err(AuthDeskError::InvalidParameter(
                "La lista de IDs no coincide con la cantidad de cuentas".to_string(),
            ));
        }

        let mut seen = std::collections::HashSet::with_capacity(account_ids.len());
        for id in &account_ids {
            if !seen.insert(id) {
                return Err(AuthDeskError::InvalidParameter(format!(
                    "ID de cuenta duplicado en reordenamiento: {}",
                    id
                )));
            }
            if !accounts.iter().any(|a| &a.id == id) {
                return Err(AuthDeskError::InvalidParameter(format!(
                    "ID de cuenta no encontrado en reordenamiento: {}",
                    id
                )));
            }
        }

        let mut current = std::mem::take(&mut *accounts);
        let mut reordered = Vec::with_capacity(current.len());

        for id in &account_ids {
            if let Some(pos) = current.iter().position(|a| &a.id == id) {
                reordered.push(current.remove(pos));
            }
        }

        *accounts = reordered;
        drop(accounts);

        self.persist_accounts_if_vault_exists()?;
        Ok(())
    }

    fn clear_staged_buffer(&self) -> Result<(), AuthDeskError> {
        let mut staged = self.staged_import.write()?;
        for acc in staged.iter_mut() {
            acc.secret.zeroize();
        }
        staged.clear();
        Ok(())
    }

    fn stage_parsed_entries(
        &self,
        parsed: ParsedImportBatch,
    ) -> Result<ImportPreviewResultDto, AuthDeskError> {
        let vault_accounts = self.accounts.read()?;
        let mut staged = self.staged_import.write()?;
        for acc in staged.iter_mut() {
            acc.secret.zeroize();
        }
        staged.clear();

        let mut items = Vec::with_capacity(parsed.accounts.len());
        let mut ready_count = 0usize;
        let mut duplicate_count = 0usize;

        for (index, acc) in parsed.accounts.into_iter().enumerate() {
            let norm_secret = crate::otp::base32::normalize_base32(&acc.secret)?;
            let is_dup = is_duplicate_account(
                &vault_accounts,
                None,
                &acc.issuer,
                &acc.account,
                &norm_secret,
            ) || is_duplicate_account(
                &staged,
                None,
                &acc.issuer,
                &acc.account,
                &norm_secret,
            );

            if is_dup {
                duplicate_count += 1;
            } else {
                ready_count += 1;
            }

            items.push(ImportPreviewItemDto {
                index,
                issuer: acc.issuer.clone(),
                account: acc.account.clone(),
                algorithm: acc.algorithm,
                digits: acc.digits,
                period: acc.period,
                is_duplicate: is_dup,
            });
            staged.push(acc);
        }

        let skipped_count = parsed.skipped.len();
        let total_found = items.len() + skipped_count;

        Ok(ImportPreviewResultDto {
            items,
            skipped: parsed.skipped,
            total_found,
            ready_count,
            duplicate_count,
            skipped_count,
        })
    }

    pub fn stage_import_uris(
        &self,
        uris_text: &str,
    ) -> Result<ImportPreviewResultDto, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        self.clear_staged_buffer()?;
        let parsed = parse_import_uris(uris_text)?;
        self.stage_parsed_entries(parsed)
    }

    pub fn stage_import_qr_images(
        &self,
        images: Vec<QrImageInputDto>,
    ) -> Result<ImportPreviewResultDto, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        self.clear_staged_buffer()?;
        let parsed = parse_import_qr_images(&images)?;
        drop(images);
        self.stage_parsed_entries(parsed)
    }

    pub fn confirm_staged_import(
        &self,
        selected_indices: Vec<usize>,
    ) -> Result<ImportConfirmResultDto, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        if selected_indices.is_empty() {
            return Err(AuthDeskError::InvalidParameter(
                "Debe seleccionar al menos una cuenta para importar".to_string(),
            ));
        }

        let mut accounts = self.accounts.write()?;
        let mut staged = self.staged_import.write()?;
        if staged.is_empty() {
            return Err(AuthDeskError::InvalidParameter(
                "No hay cuentas preparadas para importar".to_string(),
            ));
        }

        let mut seen = HashSet::with_capacity(selected_indices.len());
        let mut unique_indices = Vec::with_capacity(selected_indices.len());
        for idx in selected_indices {
            if idx >= staged.len() {
                return Err(AuthDeskError::InvalidParameter(format!(
                    "Índice de importación fuera de rango: {}",
                    idx
                )));
            }
            if seen.insert(idx) {
                unique_indices.push(idx);
            }
        }

        let prev_len = accounts.len();
        let mut imported_count = 0usize;
        let mut skipped_duplicates = 0usize;

        for idx in unique_indices {
            let cand = &staged[idx];
            let norm_secret = crate::otp::base32::normalize_base32(&cand.secret)?;
            if is_duplicate_account(
                &accounts,
                None,
                &cand.issuer,
                &cand.account,
                &norm_secret,
            ) {
                skipped_duplicates += 1;
                continue;
            }
            let id = format!("acc_{}_{}", std::process::id(), rand::random::<u64>());
            let new_acc = Account::new(
                id,
                cand.issuer.clone(),
                cand.account.clone(),
                norm_secret,
                cand.algorithm,
                cand.digits,
                cand.period,
                cand.account_type,
                cand.counter,
            )?;
            accounts.push(new_acc);
            imported_count += 1;
        }

        for acc in staged.iter_mut() {
            acc.secret.zeroize();
        }
        staged.clear();
        drop(staged);
        drop(accounts);

        if imported_count > 0 {
            if let Err(err) = self.persist_accounts_if_vault_exists() {
                if let Ok(mut accounts) = self.accounts.write() {
                    for acc in accounts[prev_len..].iter_mut() {
                        acc.secret.zeroize();
                    }
                    accounts.truncate(prev_len);
                }
                return Err(err);
            }
        }

        Ok(ImportConfirmResultDto {
            imported_count,
            skipped_duplicates,
        })
    }

    pub fn cancel_staged_import(&self) -> Result<(), AuthDeskError> {
        self.clear_staged_buffer()
    }

    fn verify_export_credential(
        &self,
        credential: Option<&Zeroizing<String>>,
    ) -> Result<(), AuthDeskError> {
        let bytes = safe_read_file(&self.vault_path)?;
        let env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        env.validate()?;

        if !env.passwordless {
            let pwd = credential
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AuthDeskError::Vault(
                        "Credenciales inválidas: se requiere la contraseña maestra".to_string(),
                    )
                })?;
            let _mk = unwrap_envelope_master_key(&env, pwd.as_str()).map_err(|_| {
                AuthDeskError::Vault("Contraseña incorrecta: credenciales inválidas".to_string())
            })?;
            return Ok(());
        }

        if self.is_pin_enabled() {
            let failed = self.pin_failed_attempts.load(Ordering::SeqCst);
            if failed >= 5 {
                let _ = self.lock_vault();
                return Err(AuthDeskError::Vault(
                    "PIN bloqueado por alcanzar 5 intentos fallidos. Reinicie la aplicación para volver a intentar.".to_string(),
                ));
            }

            let pin = credential.ok_or_else(|| {
                AuthDeskError::Vault("Credenciales inválidas: se requiere el PIN".to_string())
            })?;
            if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
                return Err(AuthDeskError::Vault(
                    "El PIN debe tener exactamente 6 dígitos numéricos".to_string(),
                ));
            }
            if !self.keyring.is_available() {
                return Err(AuthDeskError::Vault(
                    "Keyring del sistema no disponible".to_string(),
                ));
            }
            let device_key = self
                .keyring
                .get_device_key()?
                .ok_or_else(|| AuthDeskError::Vault("PIN no configurado".to_string()))?;
            let blob = self
                .keyring
                .get_pin_blob()?
                .ok_or_else(|| AuthDeskError::Vault("PIN no configurado".to_string()))?;

            let salt = BASE64
                .decode(blob.salt_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
            let params = Argon2Params {
                m_cost_kib: blob.m_cost_kib,
                t_cost: blob.t_cost,
                p_cost: blob.p_cost,
            };
            let mut pin_kek = derive_pin_kek(pin.as_str(), &salt, &device_key.key, &params)?;

            let nonce_bytes = BASE64
                .decode(blob.nonce_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
            let nonce: [u8; 24] = nonce_bytes
                .try_into()
                .map_err(|_| AuthDeskError::Vault("Invalid PIN nonce length".to_string()))?;
            let ct = BASE64
                .decode(blob.ciphertext_b64.as_bytes())
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;

            let mk_res = decrypt_master_key(&ct, &nonce, &pin_kek, PIN_AAD);
            pin_kek.zeroize();

            match mk_res {
                Ok(_mk) => {
                    self.pin_failed_attempts.store(0, Ordering::SeqCst);
                    return Ok(());
                }
                Err(_) => {
                    let new_failed = self.pin_failed_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                    if new_failed >= 5 {
                        let _ = self.lock_vault();
                        return Err(AuthDeskError::Vault(
                            "PIN bloqueado por alcanzar 5 intentos fallidos. Reinicie la aplicación para volver a intentar.".to_string(),
                        ));
                    }
                    return Err(AuthDeskError::Vault(format!(
                        "PIN incorrecto. Intentos restantes: {}",
                        5 - new_failed
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn export_vault_qr_batches(
        &self,
        mut credential: Option<String>,
        confirmed_warning: bool,
    ) -> Result<ExportQrResultDto, AuthDeskError> {
        let cred_z = credential.take().map(Zeroizing::new);
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        if !confirmed_warning {
            return Err(AuthDeskError::InvalidParameter(
                "Debe confirmar la advertencia de seguridad antes de exportar".to_string(),
            ));
        }

        self.verify_export_credential(cred_z.as_ref())?;
        drop(cred_z);

        let accounts = self.accounts.read()?.clone();
        encode_export_qr_batches(&accounts)
    }

    fn persist_accounts_if_vault_exists(&self) -> Result<(), AuthDeskError> {
        if !self.vault_path.exists() {
            return Ok(());
        }
        let mk_guard = self.master_key.read()?;
        let mk = match mk_guard.as_ref() {
            Some(k) => k,
            None => return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string())),
        };

        let bytes = safe_read_file(&self.vault_path)?;
        let mut env: VaultEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        env.updated_at = now;

        let payload_obj = VaultPayload {
            version: env.version,
            accounts: self.accounts.read()?.clone(),
        };
        let mut payload_bytes = serde_json::to_vec(&payload_obj)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let payload_aad = compute_payload_aad(env.version, now);
        let (payload_ct, payload_nonce) = encrypt_payload(&payload_bytes, mk, &payload_aad)?;
        payload_bytes.zeroize();

        env.payload = EncryptedBlob {
            nonce_b64: BASE64.encode(&payload_nonce),
            ciphertext_b64: BASE64.encode(&payload_ct),
        };
        env.validate()?;

        let json = serde_json::to_vec_pretty(&env)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        atomic_write_file(&self.vault_path, &json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_new_defaults_to_locked_with_zero_accounts() {
        assert!(AppState::new().is_locked());
        let state = AppState::with_path(
            std::env::temp_dir().join(format!("authdesk_fresh_locked_{}.enc", rand::random::<u64>())),
        );
        let status = state.get_vault_status();
        assert!(status.locked, "Fresh AppState must default to locked");
        assert_eq!(status.account_count, 0, "Locked state must report 0 accounts");
        assert!(state.is_locked());
        assert!(state.get_current_codes().is_err(), "Accessing codes when locked must error");
        assert!(state.list_account_summaries().is_err(), "Listing accounts when locked must error");
    }

    #[test]
    fn test_state_default_accounts_valid() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let accounts = state.accounts.read().unwrap();
        assert!(accounts.len() >= 4);

        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"test-github-1"));
        assert!(ids.contains(&"test-google-2"));
        assert!(ids.contains(&"test-aws-3"));
        assert!(ids.contains(&"test-proton-4"));
    }

    #[test]
    fn test_state_countdown_boundaries() {
        let state = AppState::with_accounts(AppState::default_test_accounts());

        let codes_300 = state.get_codes_at(300).expect("Debe calcular códigos");
        for c in codes_300.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 30);
        }

        let codes_315 = state.get_codes_at(315).expect("Debe calcular códigos");
        for c in codes_315.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 15);
        }

        let codes_329 = state.get_codes_at(329).expect("Debe calcular códigos");
        for c in codes_329.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 1);
        }
    }

    #[test]
    fn test_state_rfc_vectors_matching() {
        let state = AppState::with_accounts(AppState::default_test_accounts());

        let codes = state.get_codes_at(1234567890).expect("Debe calcular códigos");

        let aws = codes.iter().find(|c| c.id == "test-aws-3").unwrap();
        assert_eq!(aws.code, "005924");
        assert_eq!(aws.digits, 6);

        let proton = codes.iter().find(|c| c.id == "test-proton-4").unwrap();
        assert_eq!(proton.code, "91819424");
        assert_eq!(proton.digits, 8);
    }

    #[test]
    fn test_state_add_and_delete() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let initial_count = state.accounts.read().unwrap().len();

        let new_acc = Account::new(
            "custom-test-id".to_string(),
            "Custom Issuer".to_string(),
            "user@custom.org".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
            Algorithm::Sha1,
            6,
            30,
            AccountType::Totp,
            None,
        ).unwrap();

        state.add_account(new_acc).unwrap();
        assert_eq!(state.accounts.read().unwrap().len(), initial_count + 1);

        let deleted = state.delete_account("custom-test-id").unwrap();
        assert!(deleted);
        assert_eq!(state.accounts.read().unwrap().len(), initial_count);

        let non_existent = state.delete_account("non-existent-id").unwrap();
        assert!(!non_existent);
    }

    #[test]
    fn test_state_summaries_have_no_secrets() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let summaries = state.list_account_summaries().unwrap();
        assert_eq!(summaries.len(), state.accounts.read().unwrap().len());

        let json = serde_json::to_string(&summaries).unwrap();
        assert!(!json.contains("secret"));
    }

    #[test]
    fn test_vault_lifecycle_init_lock_unlock() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_lifecycle_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");

        let state = AppState::with_path(vault_file.clone());
        let st_init = state.get_vault_status();
        assert!(!st_init.initialized);
        assert!(st_init.locked);
        assert_eq!(st_init.account_count, 0);

        assert!(state.get_current_codes().is_err());

        state.init_vault("SecurePassword123!").unwrap();
        let st_unlocked = state.get_vault_status();
        assert!(st_unlocked.initialized);
        assert!(!st_unlocked.locked);

        let acc = Account::new(
            "custom-1".to_string(),
            "TestService".to_string(),
            "test@user.org".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
            Algorithm::Sha1,
            6,
            30,
            AccountType::Totp,
            None,
        ).unwrap();
        state.add_account(acc).unwrap();
        assert_eq!(state.get_vault_status().account_count, 1);

        state.lock_vault().unwrap();
        let st_locked = state.get_vault_status();
        assert!(st_locked.initialized);
        assert!(st_locked.locked);
        assert_eq!(st_locked.account_count, 0);
        assert!(state.get_current_codes().is_err());

        assert!(state.unlock_vault("WrongPassword").is_err());
        assert!(state.get_vault_status().locked);

        state.unlock_vault("SecurePassword123!").unwrap();
        assert!(!state.get_vault_status().locked);
        assert_eq!(state.get_vault_status().account_count, 1);
        let codes = state.get_current_codes().unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].issuer, "TestService");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // [ENC-B64::cnB0|Z2Ft|cm9k]
    #[test]
    fn test_add_account_duplicate_exact_match_rejected() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = AddAccountDto {
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Some(Algorithm::Sha1),
            digits: Some(6),
            period: Some(30),
        };
        let res = state.add_account_dto(dto);
        assert!(matches!(res, Err(AuthDeskError::DuplicateAccount(_))));
    }

    #[test]
    fn test_add_account_duplicate_case_and_whitespace_insensitivity() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = AddAccountDto {
            issuer: "  github  ".to_string(),
            account: " OCTOCAT@GITHUB.COM ".to_string(),
            secret: "  jbsw-y3dp-ehpk-3pxp  ".to_string(),
            algorithm: Some(Algorithm::Sha1),
            digits: Some(6),
            period: Some(30),
        };
        let res = state.add_account_dto(dto);
        assert!(matches!(res, Err(AuthDeskError::DuplicateAccount(_))));
    }

    #[test]
    fn test_add_account_same_issuer_account_different_secret_allowed() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = AddAccountDto {
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
            algorithm: Some(Algorithm::Sha1),
            digits: Some(6),
            period: Some(30),
        };
        let res = state.add_account_dto(dto);
        assert!(res.is_ok());
    }

    #[test]
    fn test_add_account_same_secret_different_issuer_or_account_allowed() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = AddAccountDto {
            issuer: "GitLab".to_string(),
            account: "octocat@gitlab.com".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Some(Algorithm::Sha1),
            digits: Some(6),
            period: Some(30),
        };
        let res = state.add_account_dto(dto);
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_account_retains_secret_when_none_or_empty() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "test-github-1".to_string(),
            issuer: "GitHub Updated".to_string(),
            account: "octocat-updated@github.com".to_string(),
            secret: None,
            algorithm: Some(Algorithm::Sha1),
            digits: Some(8),
            period: Some(60),
        };
        let summary = state.update_account_dto(dto).unwrap();
        assert_eq!(summary.issuer, "GitHub Updated");
        assert_eq!(summary.account, "octocat-updated@github.com");
        assert_eq!(summary.digits, 8);
        assert_eq!(summary.period, 60);

        let accounts = state.accounts.read().unwrap();
        let updated = accounts.iter().find(|a| a.id == "test-github-1").unwrap();
        assert_eq!(updated.secret, "JBSWY3DPEHPK3PXP");

        drop(accounts);
        let dto_empty = UpdateAccountDto {
            id: "test-github-1".to_string(),
            issuer: "GitHub Updated Again".to_string(),
            account: "octocat-updated@github.com".to_string(),
            secret: Some("   ".to_string()),
            algorithm: None,
            digits: None,
            period: None,
        };
        let summary2 = state.update_account_dto(dto_empty).unwrap();
        assert_eq!(summary2.issuer, "GitHub Updated Again");
        let accounts2 = state.accounts.read().unwrap();
        let updated2 = accounts2.iter().find(|a| a.id == "test-github-1").unwrap();
        assert_eq!(updated2.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_update_account_self_duplicate_ignored() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "test-github-1".to_string(),
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: None,
            algorithm: Some(Algorithm::Sha1),
            digits: Some(6),
            period: Some(45),
        };
        let res = state.update_account_dto(dto);
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_account_duplicate_against_another_account_rejected() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "test-google-2".to_string(),
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: None,
            digits: None,
            period: None,
        };
        let res = state.update_account_dto(dto);
        assert!(matches!(res, Err(AuthDeskError::DuplicateAccount(_))));
    }

    #[test]
    fn test_update_account_new_valid_secret() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "test-github-1".to_string(),
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: Some("GEZDGNBVGY3TQOJQ".to_string()),
            algorithm: None,
            digits: None,
            period: None,
        };
        let res = state.update_account_dto(dto);
        assert!(res.is_ok());
        let accounts = state.accounts.read().unwrap();
        let updated = accounts.iter().find(|a| a.id == "test-github-1").unwrap();
        assert_eq!(updated.secret, "GEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn test_update_account_invalid_secret_rejected() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "test-github-1".to_string(),
            issuer: "GitHub".to_string(),
            account: "octocat@github.com".to_string(),
            secret: Some("INVALID!BASE32#".to_string()),
            algorithm: None,
            digits: None,
            period: None,
        };
        let res = state.update_account_dto(dto);
        assert!(matches!(res, Err(AuthDeskError::Base32Decode(_))));
    }

    #[test]
    fn test_update_account_non_existent_id() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let dto = UpdateAccountDto {
            id: "non-existent-id".to_string(),
            issuer: "Whatever".to_string(),
            account: "nobody".to_string(),
            secret: None,
            algorithm: None,
            digits: None,
            period: None,
        };
        let res = state.update_account_dto(dto);
        assert!(matches!(res, Err(AuthDeskError::AccountNotFound(_))));
    }

    #[test]
    fn test_delete_account_zeroizes_secret_and_persists() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_delete_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file.clone());
        state.init_vault("Pass1234!").unwrap();

        let acc = Account::new(
            "del-1".to_string(),
            "To Delete".to_string(),
            "user@del.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
            Algorithm::Sha1,
            6,
            30,
            AccountType::Totp,
            None,
        ).unwrap();
        state.add_account(acc).unwrap();
        assert_eq!(state.accounts.read().unwrap().len(), 1);

        let deleted = state.delete_account("del-1").unwrap();
        assert!(deleted);
        assert_eq!(state.accounts.read().unwrap().len(), 0);

        let deleted_again = state.delete_account("del-1").unwrap();
        assert!(!deleted_again);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_reorder_accounts_valid_permutation() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let ids = vec![
            "test-cloudflare-5".to_string(),
            "test-proton-4".to_string(),
            "test-google-2".to_string(),
            "test-aws-3".to_string(),
            "test-github-1".to_string(),
        ];
        state.reorder_accounts(ids.clone()).unwrap();
        let accounts = state.accounts.read().unwrap();
        let current_ids: Vec<String> = accounts.iter().map(|a| a.id.clone()).collect();
        assert_eq!(current_ids, ids);
    }

    #[test]
    fn test_reorder_accounts_invalid_inputs() {
        let state = AppState::with_accounts(AppState::default_test_accounts());
        let initial_ids: Vec<String> = state.accounts.read().unwrap().iter().map(|a| a.id.clone()).collect();

        let too_few = vec!["test-github-1".to_string(), "test-google-2".to_string()];
        assert!(matches!(state.reorder_accounts(too_few), Err(AuthDeskError::InvalidParameter(_))));

        let dups = vec![
            "test-github-1".to_string(),
            "test-github-1".to_string(),
            "test-aws-3".to_string(),
            "test-proton-4".to_string(),
            "test-cloudflare-5".to_string(),
        ];
        assert!(matches!(state.reorder_accounts(dups), Err(AuthDeskError::InvalidParameter(_))));

        let unknown = vec![
            "test-github-1".to_string(),
            "test-google-2".to_string(),
            "test-aws-3".to_string(),
            "test-proton-4".to_string(),
            "unknown-id".to_string(),
        ];
        assert!(matches!(state.reorder_accounts(unknown), Err(AuthDeskError::InvalidParameter(_))));

        let final_ids: Vec<String> = state.accounts.read().unwrap().iter().map(|a| a.id.clone()).collect();
        assert_eq!(final_ids, initial_ids);
    }

    #[test]
    fn test_locked_vault_guards() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_locked_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file.clone());

        let add_dto = AddAccountDto {
            issuer: "Test".to_string(),
            account: "user".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: None,
            digits: None,
            period: None,
        };
        assert!(matches!(state.add_account_dto(add_dto), Err(AuthDeskError::Vault(_))));

        let upd_dto = UpdateAccountDto {
            id: "any".to_string(),
            issuer: "Test".to_string(),
            account: "user".to_string(),
            secret: None,
            algorithm: None,
            digits: None,
            period: None,
        };
        assert!(matches!(state.update_account_dto(upd_dto), Err(AuthDeskError::Vault(_))));

        assert!(matches!(state.delete_account("any"), Err(AuthDeskError::Vault(_))));
        assert!(matches!(state.reorder_accounts(vec![]), Err(AuthDeskError::Vault(_))));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // [ENC-B64::cnB0|Z2Ft|cm9k]
    #[test]
    fn test_passwordless_vault_unit_lifecycle() {
        crate::crypto::keyring::enable_test_keyring();
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_pwless_unit_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file);

        assert!(state.init_vault_passwordless().is_ok());
        let status = state.get_vault_status();
        assert!(status.passwordless);
        assert!(!status.locked);

        assert_eq!(state.load_demo_accounts().unwrap(), 5);
        assert_eq!(state.load_demo_accounts().unwrap(), 0);

        assert!(state.lock_vault().is_ok());
        assert!(state.is_locked());

        let auto_status = state.get_vault_status();
        assert!(auto_status.passwordless);
        assert!(!auto_status.locked);
        assert_eq!(auto_status.account_count, 5);

        assert_eq!(state.remove_demo_accounts().unwrap(), 5);
        assert_eq!(state.remove_demo_accounts().unwrap(), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_is_passwordless_helper_transitions() {
        crate::crypto::keyring::enable_test_keyring();
        let tmp_dir = std::env::temp_dir().join(format!(
            "authdesk_is_pwless_{}",
            rand::random::<u64>()
        ));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file);

        assert!(!state.is_passwordless());
        assert!(!state.can_lock_vault());

        state.init_vault_passwordless().unwrap();
        assert!(state.is_passwordless());
        assert!(!state.can_lock_vault());

        state.set_pin("123456".to_string()).unwrap();
        assert!(state.is_pin_enabled());
        assert!(state.can_lock_vault());

        state.lock_vault().unwrap();
        assert!(state.is_locked());
        assert!(!state.auto_unlock_if_passwordless().unwrap());
        let st_locked = state.get_vault_status();
        assert!(st_locked.locked);
        assert!(st_locked.passwordless);
        assert!(st_locked.pin_enabled);

        state.unlock_with_pin("123456".to_string()).unwrap();
        assert!(!state.is_locked());

        state.disable_pin().unwrap();
        assert!(!state.is_pin_enabled());
        assert!(!state.can_lock_vault());

        state.lock_vault().unwrap();
        let st_auto = state.get_vault_status();
        assert!(!st_auto.locked);

        state
            .set_master_password(None, "StrongPassword123!")
            .unwrap();
        assert!(!state.is_passwordless());
        assert!(state.can_lock_vault());

        state.remove_master_password("StrongPassword123!").unwrap();
        assert!(state.is_passwordless());
        assert!(!state.can_lock_vault());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // [ENC-B64::cnB0|Z2Ft|cm9k]
    #[test]
    fn test_window_settings_unit_controls() {
        let state = AppState::new();
        let default_cfg = state.get_window_settings();
        assert_eq!(default_cfg.mode, "popup");
        assert_eq!(default_cfg.popup_position, "top-right");
        assert!(default_cfg.always_on_top);
        assert!(!default_cfg.auto_hide_on_blur);
        assert!(!default_cfg.resizable);

        assert!(state.set_window_mode("taskbar").is_ok());
        assert_eq!(state.get_window_settings().mode, "normal");

        assert!(state.set_window_mode("floating").is_ok());
        assert_eq!(state.get_window_settings().mode, "popup");

        assert!(state.set_window_mode("normal").is_ok());
        assert_eq!(state.get_window_settings().mode, "normal");

        assert!(state.set_window_mode("tray-popup").is_ok());
        assert_eq!(state.get_window_settings().mode, "popup");

        assert!(state.set_window_mode("invalid-mode").is_err());
        assert_eq!(state.get_window_settings().mode, "popup");

        assert!(state.set_popup_position("center").is_ok());
        assert_eq!(state.get_window_settings().popup_position, "center");

        assert!(state.set_always_on_top(false).is_ok());
        assert!(!state.get_window_settings().always_on_top);

        assert!(state.set_auto_hide_on_blur(true).is_ok());
        assert!(state.get_window_settings().auto_hide_on_blur);

        assert!(state.set_window_resizable(true).is_ok());
        assert!(state.get_window_settings().resizable);
        assert!(state.set_window_resizable(false).is_ok());
        assert!(!state.get_window_settings().resizable);
    }

    #[test]
    fn test_passwordless_pin_lockout_preserves_lock_and_blocks_auto_unlock() {
        crate::crypto::keyring::enable_test_keyring();
        let tmp_dir = std::env::temp_dir().join(format!(
            "authdesk_pwless_pin_lockout_{}",
            rand::random::<u64>()
        ));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file);

        state.init_vault_passwordless().unwrap();
        state.set_pin("123456".to_string()).unwrap();
        state.lock_vault().unwrap();
        assert!(state.is_locked());

        for i in 1..=4 {
            let err = state.unlock_with_pin("000000".to_string()).unwrap_err();
            assert!(err.to_string().contains(&(5 - i).to_string()));
        }

        let err5 = state.unlock_with_pin("000000".to_string()).unwrap_err();
        assert!(err5.to_string().contains("bloqueado"));

        let status = state.get_vault_status();
        assert!(status.locked);
        assert!(status.pin_enabled);
        assert_eq!(status.pin_attempts_remaining, Some(0));

        assert!(!state.auto_unlock_if_passwordless().unwrap());
        assert!(state.is_locked());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_password_change_rotates_mk_and_purges_bak() {
        crate::crypto::keyring::enable_test_keyring();
        let tmp_dir = std::env::temp_dir().join(format!(
            "authdesk_pw_change_bak_{}",
            rand::random::<u64>()
        ));
        let vault_file = tmp_dir.join("vault.enc");
        let bak_file = tmp_dir.join("vault.enc.bak");
        let state = AppState::with_path(vault_file.clone());

        state.init_vault("OldPassword123!").unwrap();
        let old_env: VaultEnvelope =
            serde_json::from_slice(&safe_read_file(&vault_file).unwrap()).unwrap();
        let old_mk = unwrap_envelope_master_key(&old_env, "OldPassword123!").unwrap();

        state
            .change_master_password("OldPassword123!", "NewPassword456!")
            .unwrap();
        state.lock_vault().unwrap();
        assert!(state.is_locked());

        assert!(bak_file.exists());
        std::fs::copy(&bak_file, &vault_file).unwrap();

        assert!(state.unlock_vault("OldPassword123!").is_err());
        assert!(state.is_locked());

        state.unlock_vault("NewPassword456!").unwrap();
        assert!(!state.is_locked());

        let bak_env: VaultEnvelope =
            serde_json::from_slice(&safe_read_file(&bak_file).unwrap()).unwrap();
        let new_mk = unwrap_envelope_master_key(&bak_env, "NewPassword456!").unwrap();
        assert_ne!(old_mk.as_bytes(), new_mk.as_bytes());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_staged_import_zero_secret_preview_confirm_cancel_and_lock() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "authdesk_staged_import_{}",
            rand::random::<u64>()
        ));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file);

        assert!(matches!(
            state.stage_import_uris("otpauth://totp/GitHub:u@g.com?secret=JBSWY3DPEHPK3PXP"),
            Err(AuthDeskError::Vault(_))
        ));

        state.init_vault("StrongPass123!").unwrap();
        state
            .add_account_dto(AddAccountDto {
                issuer: "GitHub".to_string(),
                account: "existing@github.com".to_string(),
                secret: "JBSWY3DPEHPK3PXP".to_string(),
                algorithm: Some(Algorithm::Sha1),
                digits: Some(6),
                period: Some(30),
            })
            .unwrap();

        let uris = [
            "otpauth://totp/GitHub:existing@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "otpauth://totp/Proton:sec@proton.me?secret=GEZDGNBVGY3TQOJQ&issuer=Proton&algorithm=SHA256&digits=8",
            "otpauth://totp/Proton:sec@proton.me?secret=GEZDGNBVGY3TQOJQ&issuer=Proton&algorithm=SHA256&digits=8",
            "otpauth://hotp/Legacy:hotp@test.io?secret=JBSWY3DPEHPK3PXP&counter=1",
        ]
        .join("\n");

        let preview = state.stage_import_uris(&uris).unwrap();
        assert_eq!(preview.total_found, 4);
        assert_eq!(preview.ready_count, 1);
        assert_eq!(preview.duplicate_count, 2);
        assert_eq!(preview.skipped_count, 1);
        assert_eq!(preview.items.len(), 3);
        assert!(preview.items[0].is_duplicate);
        assert!(!preview.items[1].is_duplicate);
        assert!(preview.items[2].is_duplicate);

        let preview_json = serde_json::to_string(&preview).unwrap();
        assert!(!preview_json.contains("JBSWY3DPEHPK3PXP"));
        assert!(!preview_json.contains("GEZDGNBVGY3TQOJQ"));
        assert!(!preview_json.contains("secret"));
        assert_eq!(state.staged_import.read().unwrap().len(), 3);

        assert!(matches!(
            state.confirm_staged_import(vec![]),
            Err(AuthDeskError::InvalidParameter(_))
        ));
        assert!(matches!(
            state.confirm_staged_import(vec![99]),
            Err(AuthDeskError::InvalidParameter(_))
        ));
        assert_eq!(state.staged_import.read().unwrap().len(), 3);

        let confirmed = state.confirm_staged_import(vec![0, 1, 2]).unwrap();
        assert_eq!(confirmed.imported_count, 1);
        assert_eq!(confirmed.skipped_duplicates, 2);
        assert_eq!(state.staged_import.read().unwrap().len(), 0);
        assert_eq!(state.accounts.read().unwrap().len(), 2);

        state
            .stage_import_uris("otpauth://totp/GitLab:dev@gl.com?secret=JBSWY3DPEHPK3PXP&issuer=GitLab")
            .unwrap();
        assert_eq!(state.staged_import.read().unwrap().len(), 1);
        state.cancel_staged_import().unwrap();
        assert_eq!(state.staged_import.read().unwrap().len(), 0);
        assert_eq!(state.accounts.read().unwrap().len(), 2);

        state
            .stage_import_uris("otpauth://totp/AWS:ops@aws.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS")
            .unwrap();
        assert_eq!(state.staged_import.read().unwrap().len(), 1);
        state.lock_vault().unwrap();
        assert_eq!(state.staged_import.read().unwrap().len(), 0);

        state.unlock_vault("StrongPass123!").unwrap();
        assert_eq!(state.accounts.read().unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_export_vault_qr_batches_reauth_modes_and_security() {
        crate::crypto::keyring::enable_test_keyring();
        let tmp_dir = std::env::temp_dir().join(format!(
            "authdesk_export_reauth_{}",
            rand::random::<u64>()
        ));
        let vault_file = tmp_dir.join("vault.enc");
        let state = AppState::with_path(vault_file);

        state.init_vault("MasterSecret123!").unwrap();
        assert!(matches!(
            state.export_vault_qr_batches(Some("MasterSecret123!".to_string()), false),
            Err(AuthDeskError::InvalidParameter(_))
        ));
        assert!(matches!(
            state.export_vault_qr_batches(Some("WrongPass".to_string()), true),
            Err(AuthDeskError::Vault(_))
        ));
        assert!(matches!(
            state.export_vault_qr_batches(None, true),
            Err(AuthDeskError::Vault(_))
        ));
        assert!(matches!(
            state.export_vault_qr_batches(Some("MasterSecret123!".to_string()), true),
            Err(AuthDeskError::InvalidParameter(_))
        ));

        for i in 0..12 {
            state
                .add_account_dto(AddAccountDto {
                    issuer: format!("Issuer{}", i),
                    account: format!("user{}@example.com", i),
                    secret: "JBSWY3DPEHPK3PXP".to_string(),
                    algorithm: Some(Algorithm::Sha1),
                    digits: Some(6),
                    period: Some(30),
                })
                .unwrap();
        }

        let exported = state
            .export_vault_qr_batches(Some("MasterSecret123!".to_string()), true)
            .unwrap();
        assert_eq!(exported.total_accounts, 12);
        assert_eq!(exported.batches.len(), 2);
        assert_eq!(exported.batches[0].account_count, 10);
        assert_eq!(exported.batches[1].account_count, 2);

        state.remove_master_password("MasterSecret123!").unwrap();
        assert!(state.is_passwordless());
        assert!(!state.is_pin_enabled());

        let pwless_export = state.export_vault_qr_batches(None, true).unwrap();
        assert_eq!(pwless_export.total_accounts, 12);
        assert_eq!(pwless_export.batches.len(), 2);

        state.set_pin("654321".to_string()).unwrap();
        assert!(state.is_pin_enabled());
        assert!(matches!(
            state.export_vault_qr_batches(None, true),
            Err(AuthDeskError::Vault(_))
        ));
        assert!(matches!(
            state.export_vault_qr_batches(Some("000000".to_string()), true),
            Err(AuthDeskError::Vault(_))
        ));
        let pin_export = state
            .export_vault_qr_batches(Some("654321".to_string()), true)
            .unwrap();
        assert_eq!(pin_export.total_accounts, 12);

        state.lock_vault().unwrap();
        assert!(matches!(
            state.export_vault_qr_batches(Some("654321".to_string()), true),
            Err(AuthDeskError::Vault(_))
        ));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
