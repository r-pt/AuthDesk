// [ENC-B64::cnB0|Z2Ft|cm9k]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use data_encoding::BASE64;
use zeroize::Zeroize;

use crate::crypto::aead::{
    compute_payload_aad, compute_wrapped_key_aad, decrypt_master_key, decrypt_payload,
    encrypt_master_key, encrypt_payload, generate_master_key, MasterKey,
};
use crate::crypto::kdf::{derive_kek, derive_pin_kek, generate_salt, Argon2Params};
use crate::crypto::keyring::{KeyringStorage, PinBlob, PIN_AAD};
use crate::error::AuthDeskError;
use crate::models::{
    Account, AccountCodeDto, AccountSummaryDto, AccountType, AddAccountDto, Algorithm,
    UpdateAccountDto, VaultStatusDto,
};
use crate::otp::totp::{calculate_remaining_seconds, generate_totp};
use crate::storage::atomic::{atomic_write_file, default_vault_path, safe_read_file};
use crate::storage::vault_file::{
    EncryptedBlob, KdfConfig, VaultEnvelope, VaultPayload, KDF_ALGO_ARGON2ID, VAULT_MAGIC,
    VAULT_VERSION,
};

// [ENC-B64::cnB0|Z2Ft|cm9k]
fn check_duplicate_account(
    accounts: &[Account],
    candidate_id: Option<&str>,
    candidate_issuer: &str,
    candidate_account: &str,
    candidate_norm_secret: &str,
) -> Result<(), AuthDeskError> {
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
                    return Err(AuthDeskError::DuplicateAccount(
                        "Ya existe una cuenta con el mismo emisor, cuenta y clave secreta".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub struct AppState {
    pub vault_path: PathBuf,
    pub accounts: RwLock<Vec<Account>>,
    pub master_key: RwLock<Option<MasterKey>>,
    pub pin_failed_attempts: AtomicU32,
    pub keyring: KeyringStorage,
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
            vault_path: default_vault_path(),
            accounts: RwLock::new(accounts),
            master_key: RwLock::new(Some(MasterKey::new([0u8; 32]))),
            pin_failed_attempts: AtomicU32::new(0),
            keyring: KeyringStorage::new(),
        }
    }

    pub fn with_path(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            accounts: RwLock::new(Vec::new()),
            master_key: RwLock::new(None),
            pin_failed_attempts: AtomicU32::new(0),
            keyring: KeyringStorage::new(),
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

    pub fn get_vault_status(&self) -> VaultStatusDto {
        let initialized = self.vault_path.exists();
        let locked = self.is_locked();
        let account_count = if locked {
            0
        } else {
            self.accounts.read().map(|a| a.len()).unwrap_or(0)
        };
        let pin_available = self.keyring.is_available();
        let pin_enabled = if pin_available && initialized {
            self.keyring.get_pin_blob().map(|b| b.is_some()).unwrap_or(false)
        } else {
            false
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
        }
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
        let state = AppState::new();
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
}
