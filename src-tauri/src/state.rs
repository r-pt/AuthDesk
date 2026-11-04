// [ENC-B64::cnB0|Z2Ft|cm9k]
use std::path::PathBuf;
use std::sync::RwLock;
use data_encoding::BASE64;
use zeroize::Zeroize;

use crate::crypto::aead::{
    compute_payload_aad, compute_wrapped_key_aad, decrypt_master_key, decrypt_payload,
    encrypt_master_key, encrypt_payload, generate_master_key, MasterKey,
};
use crate::crypto::kdf::{derive_kek, generate_salt, Argon2Params};
use crate::error::AuthDeskError;
use crate::models::{
    Account, AccountCodeDto, AccountSummaryDto, AccountType, AddAccountDto, Algorithm,
    VaultStatusDto,
};
use crate::otp::totp::{calculate_remaining_seconds, generate_totp};
use crate::storage::atomic::{atomic_write_file, default_vault_path, safe_read_file};
use crate::storage::vault_file::{
    EncryptedBlob, KdfConfig, VaultEnvelope, VaultPayload, KDF_ALGO_ARGON2ID, VAULT_MAGIC,
    VAULT_VERSION,
};

pub struct AppState {
    pub vault_path: PathBuf,
    pub accounts: RwLock<Vec<Account>>,
    pub master_key: RwLock<Option<MasterKey>>,
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
        }
    }

    pub fn with_path(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            accounts: RwLock::new(Vec::new()),
            master_key: RwLock::new(None),
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
        VaultStatusDto {
            initialized,
            locked,
            account_count,
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
        self.accounts.write()?.push(account);
        self.persist_accounts_if_vault_exists()?;
        Ok(())
    }

    pub fn add_account_dto(&self, dto: AddAccountDto) -> Result<AccountSummaryDto, AuthDeskError> {
        let id = format!("acc_{}_{}", std::process::id(), rand::random::<u64>());
        let acc = Account::new(
            id,
            dto.issuer,
            dto.account,
            dto.secret,
            dto.algorithm.unwrap_or(Algorithm::Sha1),
            dto.digits.unwrap_or(6),
            dto.period.unwrap_or(30),
            AccountType::Totp,
            None,
        )?;
        let summary = acc.to_summary_dto();
        self.add_account(acc)?;
        Ok(summary)
    }

    pub fn delete_account(&self, id: &str) -> Result<bool, AuthDeskError> {
        if self.is_locked() {
            return Err(AuthDeskError::Vault("Bóveda bloqueada".to_string()));
        }
        let mut accounts = self.accounts.write()?;
        let initial_len = accounts.len();
        accounts.retain(|a| a.id != id);
        let removed = accounts.len() < initial_len;
        drop(accounts);
        if removed {
            self.persist_accounts_if_vault_exists()?;
        }
        Ok(removed)
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
}
