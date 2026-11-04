//! Adversarial Challenge Test Suite for AuthDesk Phase 2: Crypto & Storage Resilience
//!
//! Empirical verification of:
//! 1. Wrong password on `unlock_vault` (MAC authentication failure, locked state maintained, access guarded).
//! 2. Tampered ciphertext and canonical AAD tampering in vault file (rejection, no secret leaks).
//! 3. Degraded KDF parameters hard rejection (m < 65536 KiB, t < 3, p != 1, salt < 16B, invalid algo).
//! 4. POSIX permissions auto-hardening (file 0666/0644/0777 -> 0600, dir 0777/0755 -> 0700).
//! 5. Automatic disaster recovery from `vault.enc.bak` when primary is corrupted.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use data_encoding::BASE64;

use authdesk_lib::crypto::kdf::{validate_kdf_params, Argon2Params};
use authdesk_lib::models::{Account, Algorithm, AccountType};
use authdesk_lib::state::AppState;
use authdesk_lib::storage::atomic::{
    ensure_vault_dir, harden_dir_permissions, harden_file_permissions,
    safe_read_file,
};
use authdesk_lib::storage::vault_file::{
    EncryptedBlob, KdfConfig, VaultEnvelope, KDF_ALGO_ARGON2ID, VAULT_MAGIC,
    VAULT_VERSION,
};

/// Helper to generate an isolated unique temporary directory for a test
fn create_test_dir(test_name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("authdesk_adv_{}_{}", test_name, rand::random::<u64>()));
    fs::create_dir_all(&dir).expect("Failed to create test dir");
    dir
}

/// Helper to cleanup temporary directory
fn cleanup_test_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// 1. Wrong Password on `unlock_vault`
// =========================================================================

#[test]
fn test_wrong_password_unlock_mac_failure_and_state_remains_locked() {
    let dir = create_test_dir("wrong_password");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());

    let correct_password = "SuperStrongMasterPassword2026!#$";
    let wrong_password = "IncorrectPassword987!";

    // 1. Initialize vault and add account
    state.init_vault(correct_password).expect("Init vault must succeed");
    assert!(!state.is_locked(), "State should be unlocked after init");

    let test_acc = Account::new(
        "acc_test_pw".to_string(),
        "TestService".to_string(),
        "user@test.org".to_string(),
        "JBSWY3DPEHPK3PXP".to_string(),
        Algorithm::Sha1,
        6,
        30,
        AccountType::Totp,
        None,
    ).unwrap();
    state.add_account(test_acc).expect("Add account must succeed");

    // 2. Lock vault
    state.lock_vault().expect("Lock vault must succeed");
    assert!(state.is_locked(), "State must be locked");

    // 3. Attempt unlock with wrong password
    let unlock_result = state.unlock_vault(wrong_password);
    assert!(unlock_result.is_err(), "Unlock with wrong password MUST fail");
    let err_str = unlock_result.unwrap_err().to_string();
    assert!(
        err_str.contains("Authentication failed") || err_str.contains("autenticación"),
        "Error message must indicate authentication failure, got: {}",
        err_str
    );

    // 4. Verify state remains locked
    assert!(state.is_locked(), "Vault MUST remain locked after failed password");

    // 5. Verify guarded operations return error
    let codes_res = state.get_current_codes();
    assert!(codes_res.is_err(), "get_current_codes must be blocked when locked");

    let summaries_res = state.list_account_summaries();
    assert!(summaries_res.is_err(), "list_account_summaries must be blocked when locked");

    let status = state.get_vault_status();
    assert!(status.locked, "VaultStatusDto must reflect locked state");
    assert_eq!(status.account_count, 0, "Account count must be hidden when locked");

    // 6. Verify correct password unlocks successfully afterwards
    state.unlock_vault(correct_password).expect("Unlock with correct password must succeed");
    assert!(!state.is_locked(), "State must be unlocked with correct password");
    let codes = state.get_current_codes().expect("Codes should be accessible after unlocking");
    assert!(!codes.is_empty(), "Accounts should have been decrypted");

    cleanup_test_dir(&dir);
}

#[test]
fn test_empty_password_unlock_rejected() {
    let dir = create_test_dir("empty_password");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());

    state.init_vault("ValidPassword123!").expect("Init vault must succeed");
    state.lock_vault().expect("Lock must succeed");

    let unlock_res = state.unlock_vault("");
    assert!(unlock_res.is_err(), "Empty password on unlock must be rejected");
    assert!(state.is_locked());

    cleanup_test_dir(&dir);
}

// =========================================================================
// 2. Tampered Ciphertext & Canonical AAD Tampering
// =========================================================================

#[test]
fn test_tampered_wrapped_master_key_ciphertext() {
    let dir = create_test_dir("tamper_mk_ct");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());
    let password = "SecretPassword123!";

    state.init_vault(password).expect("Init vault failed");
    state.lock_vault().expect("Lock failed");

    // Read and parse envelope
    let json_bytes = fs::read(&vault_file).unwrap();
    let mut env: VaultEnvelope = serde_json::from_slice(&json_bytes).unwrap();

    // Tamper single bit in wrapped master key ciphertext
    let mut ct_bytes = BASE64.decode(env.wrapped_master_key.ciphertext_b64.as_bytes()).unwrap();
    ct_bytes[5] ^= 0x01; // flip one bit
    env.wrapped_master_key.ciphertext_b64 = BASE64.encode(&ct_bytes);

    let tampered_json = serde_json::to_vec_pretty(&env).unwrap();
    fs::write(&vault_file, tampered_json).unwrap();

    // Unlock must fail Poly1305 MAC check
    let res = state.unlock_vault(password);
    assert!(res.is_err(), "Tampered MK ciphertext must fail authentication");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Authentication failed"), "Expected auth failure, got: {}", err);
    assert!(state.is_locked());

    cleanup_test_dir(&dir);
}

#[test]
fn test_tampered_payload_ciphertext() {
    let dir = create_test_dir("tamper_payload_ct");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());
    let password = "SecretPassword123!";

    state.init_vault(password).expect("Init vault failed");
    state.lock_vault().expect("Lock failed");

    let json_bytes = fs::read(&vault_file).unwrap();
    let mut env: VaultEnvelope = serde_json::from_slice(&json_bytes).unwrap();

    // Tamper payload ciphertext (modify bit in payload bytes)
    let mut ct_bytes = BASE64.decode(env.payload.ciphertext_b64.as_bytes()).unwrap();
    ct_bytes[0] ^= 0x80; // flip high bit
    env.payload.ciphertext_b64 = BASE64.encode(&ct_bytes);

    let tampered_json = serde_json::to_vec_pretty(&env).unwrap();
    fs::write(&vault_file, tampered_json).unwrap();

    let res = state.unlock_vault(password);
    assert!(res.is_err(), "Tampered payload ciphertext must fail authentication");
    assert!(state.is_locked());

    cleanup_test_dir(&dir);
}

#[test]
fn test_aad_tampering_updated_at_fails_payload_mac() {
    let dir = create_test_dir("tamper_aad_timestamp");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());
    let password = "SecretPassword123!";

    state.init_vault(password).expect("Init vault failed");
    state.lock_vault().expect("Lock failed");

    let json_bytes = fs::read(&vault_file).unwrap();
    let mut env: VaultEnvelope = serde_json::from_slice(&json_bytes).unwrap();

    // Alter updated_at timestamp by 1 second in the envelope metadata
    env.updated_at += 1;

    let tampered_json = serde_json::to_vec_pretty(&env).unwrap();
    fs::write(&vault_file, tampered_json).unwrap();

    // Payload AAD includes updated_at: decrypt_payload must reject with MAC failure
    let res = state.unlock_vault(password);
    assert!(res.is_err(), "Tampered updated_at in AAD must fail payload MAC check");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Authentication failed"), "Expected auth failure, got: {}", err);
    assert!(state.is_locked());

    cleanup_test_dir(&dir);
}

#[test]
fn test_aad_tampering_salt_fails_wrapped_mk_mac() {
    let dir = create_test_dir("tamper_aad_salt");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());
    let password = "SecretPassword123!";

    state.init_vault(password).expect("Init vault failed");
    state.lock_vault().expect("Lock failed");

    let json_bytes = fs::read(&vault_file).unwrap();
    let mut env: VaultEnvelope = serde_json::from_slice(&json_bytes).unwrap();

    // Alter salt bytes (still valid base64 and 32 bytes)
    let mut salt = BASE64.decode(env.kdf.salt_b64.as_bytes()).unwrap();
    salt[0] ^= 0x55;
    env.kdf.salt_b64 = BASE64.encode(&salt);

    let tampered_json = serde_json::to_vec_pretty(&env).unwrap();
    fs::write(&vault_file, tampered_json).unwrap();

    // Wrapped MK AAD includes salt: decrypt_master_key must fail
    let res = state.unlock_vault(password);
    assert!(res.is_err(), "Tampered salt in AAD must fail wrapped MK MAC");
    assert!(state.is_locked());

    cleanup_test_dir(&dir);
}

// =========================================================================
// 3. Degraded KDF Parameters Hard Rejection
// =========================================================================

#[test]
fn test_degraded_kdf_parameters_rejection() {
    // 3.1 m_cost < 65536 KiB
    let p_low_m = Argon2Params { m_cost_kib: 65535, t_cost: 3, p_cost: 1 };
    assert!(validate_kdf_params(&p_low_m, 32).is_err(), "m_cost 65535 must be rejected");

    let p_zero_m = Argon2Params { m_cost_kib: 0, t_cost: 3, p_cost: 1 };
    assert!(validate_kdf_params(&p_zero_m, 32).is_err(), "m_cost 0 must be rejected");

    let p_1mib = Argon2Params { m_cost_kib: 1024, t_cost: 3, p_cost: 1 };
    assert!(validate_kdf_params(&p_1mib, 32).is_err(), "m_cost 1024 must be rejected");

    // 3.2 t_cost < 3
    let p_low_t = Argon2Params { m_cost_kib: 65536, t_cost: 2, p_cost: 1 };
    assert!(validate_kdf_params(&p_low_t, 32).is_err(), "t_cost 2 must be rejected");

    let p_zero_t = Argon2Params { m_cost_kib: 65536, t_cost: 0, p_cost: 1 };
    assert!(validate_kdf_params(&p_zero_t, 32).is_err(), "t_cost 0 must be rejected");

    // 3.3 p_cost != 1
    let p_p2 = Argon2Params { m_cost_kib: 65536, t_cost: 3, p_cost: 2 };
    assert!(validate_kdf_params(&p_p2, 32).is_err(), "p_cost 2 must be rejected");

    let p_p0 = Argon2Params { m_cost_kib: 65536, t_cost: 3, p_cost: 0 };
    assert!(validate_kdf_params(&p_p0, 32).is_err(), "p_cost 0 must be rejected");

    // 3.4 Salt length < 16 bytes
    let p_valid = Argon2Params { m_cost_kib: 65536, t_cost: 3, p_cost: 1 };
    assert!(validate_kdf_params(&p_valid, 15).is_err(), "salt 15 bytes must be rejected");
    assert!(validate_kdf_params(&p_valid, 8).is_err(), "salt 8 bytes must be rejected");
    assert!(validate_kdf_params(&p_valid, 0).is_err(), "salt 0 bytes must be rejected");
    assert!(validate_kdf_params(&p_valid, 16).is_ok(), "salt 16 bytes is allowed minimum");
    assert!(validate_kdf_params(&p_valid, 32).is_ok(), "salt 32 bytes is allowed recommended");
}

#[test]
fn test_vault_envelope_validation_rejects_degraded_parameters() {
    let mut env = VaultEnvelope {
        magic: VAULT_MAGIC.to_string(),
        version: VAULT_VERSION,
        created_at: 1710000000,
        updated_at: 1710000000,
        kdf: KdfConfig {
            algorithm: KDF_ALGO_ARGON2ID.to_string(),
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
            salt_b64: BASE64.encode(&[1u8; 32]),
        },
        wrapped_master_key: EncryptedBlob {
            nonce_b64: BASE64.encode(&[2u8; 24]),
            ciphertext_b64: BASE64.encode(&[3u8; 48]),
        },
        payload: EncryptedBlob {
            nonce_b64: BASE64.encode(&[4u8; 24]),
            ciphertext_b64: BASE64.encode(&[5u8; 32]),
        },
    };

    assert!(env.validate().is_ok(), "Base envelope should be valid");

    // Degrade m_cost
    env.kdf.m_cost_kib = 32768;
    assert!(env.validate().is_err(), "m_cost 32768 must fail envelope validation");
    env.kdf.m_cost_kib = 65536;

    // Degrade t_cost
    env.kdf.t_cost = 1;
    assert!(env.validate().is_err(), "t_cost 1 must fail envelope validation");
    env.kdf.t_cost = 3;

    // Degrade p_cost
    env.kdf.p_cost = 4;
    assert!(env.validate().is_err(), "p_cost 4 must fail envelope validation");
    env.kdf.p_cost = 1;

    // Short salt
    env.kdf.salt_b64 = BASE64.encode(&[1u8; 10]);
    assert!(env.validate().is_err(), "Salt 10B must fail envelope validation");
    env.kdf.salt_b64 = BASE64.encode(&[1u8; 32]);

    // Invalid algorithm
    env.kdf.algorithm = "PBKDF2".to_string();
    assert!(env.validate().is_err(), "Algorithm PBKDF2 must fail envelope validation");
    env.kdf.algorithm = KDF_ALGO_ARGON2ID.to_string();

    // Corrupted magic
    env.magic = "INVALID_MAGIC".to_string();
    assert!(env.validate().is_err(), "Invalid magic must fail envelope validation");
    env.magic = VAULT_MAGIC.to_string();

    // Unsupported version
    env.version = 2;
    assert!(env.validate().is_err(), "Version 2 must fail envelope validation");
    env.version = VAULT_VERSION;

    // Non-positive timestamp
    env.created_at = 0;
    assert!(env.validate().is_err(), "created_at 0 must fail envelope validation");
}

// =========================================================================
// 4. POSIX Permissions Auto-Hardening
// =========================================================================

#[test]
fn test_posix_permissions_file_hardening_from_insecure_modes() {
    let dir = create_test_dir("file_hardening");
    let vault_file = dir.join("vault.enc");

    // 1. Insecure mode 0666 (world-writable)
    fs::write(&vault_file, b"test content").unwrap();
    fs::set_permissions(&vault_file, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777, 0o666);

    harden_file_permissions(&vault_file).expect("harden_file_permissions failed");
    assert_eq!(
        fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "File mode must be auto-hardened to 0600 from 0666"
    );

    // 2. Insecure mode 0644 (world-readable)
    fs::set_permissions(&vault_file, fs::Permissions::from_mode(0o644)).unwrap();
    harden_file_permissions(&vault_file).expect("harden_file_permissions failed");
    assert_eq!(
        fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "File mode must be auto-hardened to 0600 from 0644"
    );

    // 3. Insecure mode 0777 (executable and world-writable)
    fs::set_permissions(&vault_file, fs::Permissions::from_mode(0o777)).unwrap();
    harden_file_permissions(&vault_file).expect("harden_file_permissions failed");
    assert_eq!(
        fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "File mode must be auto-hardened to 0600 from 0777"
    );

    cleanup_test_dir(&dir);
}

#[test]
fn test_posix_permissions_dir_hardening_from_insecure_modes() {
    let dir = create_test_dir("dir_hardening");

    // Insecure directory mode 0777
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o777);

    harden_dir_permissions(&dir).expect("harden_dir_permissions failed");
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700,
        "Directory mode must be hardened to 0700 from 0777"
    );

    // Insecure directory mode 0755
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    ensure_vault_dir(&dir).expect("ensure_vault_dir failed");
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700,
        "Directory mode must be hardened to 0700 from 0755 via ensure_vault_dir"
    );

    cleanup_test_dir(&dir);
}

// =========================================================================
// 5. Corrupted Primary Vault Automatic Disaster Recovery from .bak
// =========================================================================

#[test]
fn test_disaster_recovery_from_backup_when_primary_corrupted() {
    let dir = create_test_dir("disaster_recovery");
    let vault_file = dir.join("vault.enc");
    let backup_file = dir.join("vault.enc.bak");
    let state = AppState::with_path(vault_file.clone());
    let password = "DisasterRecoveryPassword2026!";

    // 1. Initialize vault and add an account so we have version 2 with backup
    state.init_vault(password).expect("Init vault failed");
    let new_acc = Account::new(
        "acc_test_recovery".to_string(),
        "RecoveryIssuer".to_string(),
        "recovery_user".to_string(),
        "JBSWY3DPEHPK3PXP".to_string(),
        Algorithm::Sha1,
        6,
        30,
        AccountType::Totp,
        None,
    ).unwrap();
    state.add_account(new_acc).expect("Add account failed");

    // Ensure backup file was created by the rotation in atomic_write_file
    assert!(backup_file.exists(), "Backup file vault.enc.bak must exist");
    let backup_content = fs::read(&backup_file).unwrap();
    assert!(!backup_content.is_empty(), "Backup file must have valid content");

    // 2. Corrupt the primary vault file by truncating to 0 bytes
    fs::write(&vault_file, b"").unwrap();
    assert_eq!(fs::metadata(&vault_file).unwrap().len(), 0);

    // 3. Lock state to clear memory
    state.lock_vault().expect("Lock failed");

    // 4. Unlock vault: safe_read_file should detect corrupted primary, restore from .bak, and decrypt
    state.unlock_vault(password).expect("Unlock MUST succeed via disaster recovery from backup");
    assert!(!state.is_locked(), "Vault must be unlocked after recovery");

    // 5. Verify vault.enc has been restored from backup
    let restored_content = fs::read(&vault_file).unwrap();
    assert_eq!(restored_content, backup_content, "Primary vault must match backup after recovery");
    let mode = fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Restored primary vault must have 0600 permissions");

    cleanup_test_dir(&dir);
}

#[test]
fn test_disaster_recovery_when_primary_has_garbage_content() {
    let dir = create_test_dir("garbage_recovery");
    let vault_file = dir.join("vault.enc");
    let _backup_file = dir.join("vault.enc.bak");
    let state = AppState::with_path(vault_file.clone());
    let password = "GarbageRecoveryPassword2026!";

    state.init_vault(password).expect("Init vault failed");
    // Write another version to ensure .bak exists
    state.add_account(Account::new(
        "acc_temp".to_string(),
        "Temp".to_string(),
        "user".to_string(),
        "JBSWY3DPEHPK3PXP".to_string(),
        Algorithm::Sha1,
        6,
        30,
        AccountType::Totp,
        None,
    ).unwrap()).unwrap();

    // Corrupt primary with invalid JSON garbage
    fs::write(&vault_file, b"<!DOCTYPE html><html><body>Error 500 Server Crash</body></html>").unwrap();
    state.lock_vault().unwrap();

    // safe_read_file should recover from .bak
    let recovered_bytes = safe_read_file(&vault_file).expect("safe_read_file must recover from .bak");
    let env: VaultEnvelope = serde_json::from_slice(&recovered_bytes).unwrap();
    assert_eq!(env.magic, VAULT_MAGIC);

    cleanup_test_dir(&dir);
}

#[test]
fn test_both_primary_and_backup_corrupted_fails_gracefully() {
    let dir = create_test_dir("both_corrupted");
    let vault_file = dir.join("vault.enc");
    let backup_file = dir.join("vault.enc.bak");

    fs::write(&vault_file, b"GARBAGE_PRIMARY").unwrap();
    fs::write(&backup_file, b"GARBAGE_BACKUP").unwrap();

    let res = safe_read_file(&vault_file);
    assert!(res.is_err(), "When both files are corrupted, must return Err without crashing");

    cleanup_test_dir(&dir);
}

// =========================================================================
// 6. Advanced Adversarial Edge Cases
// =========================================================================

#[test]
fn test_backup_file_loose_permissions_auto_hardened() {
    let dir = create_test_dir("bak_hardening");
    let vault_file = dir.join("vault.enc");
    let backup_file = dir.join("vault.enc.bak");
    let state = AppState::with_path(vault_file.clone());
    let password = "HardeningBackupPassword2026!";

    state.init_vault(password).expect("Init vault failed");
    state.add_account(Account::new(
        "acc_bak".to_string(),
        "Bak".to_string(),
        "user".to_string(),
        "JBSWY3DPEHPK3PXP".to_string(),
        Algorithm::Sha1,
        6,
        30,
        AccountType::Totp,
        None,
    ).unwrap()).unwrap();

    // Insecurely chmod .bak to 0666 and corrupt primary
    fs::set_permissions(&backup_file, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(fs::metadata(&backup_file).unwrap().permissions().mode() & 0o777, 0o666);
    fs::write(&vault_file, b"corrupted").unwrap();

    // safe_read_file must harden backup_file to 0600 and restore primary as 0600
    let res = safe_read_file(&vault_file);
    assert!(res.is_ok(), "Disaster recovery must succeed");

    assert_eq!(
        fs::metadata(&backup_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "Backup file must be auto-hardened to 0600"
    );
    assert_eq!(
        fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "Restored vault file must have 0600"
    );

    cleanup_test_dir(&dir);
}

#[test]
fn test_concurrent_lock_and_read_guards_no_deadlocks() {
    use std::sync::Arc;
    use std::thread;

    let dir = create_test_dir("concurrent_guards");
    let vault_file = dir.join("vault.enc");
    let state = Arc::new(AppState::with_path(vault_file.clone()));
    let password = "ConcurPass2026!#$";

    state.init_vault(password).unwrap();
    state.add_account(Account::new(
        "acc_c1".to_string(),
        "Concur".to_string(),
        "c@c.org".to_string(),
        "JBSWY3DPEHPK3PXP".to_string(),
        Algorithm::Sha1,
        6,
        30,
        AccountType::Totp,
        None,
    ).unwrap()).unwrap();

    let mut handles = Vec::new();
    for i in 0..10 {
        let st = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                if i % 3 == 0 {
                    let _ = st.lock_vault();
                } else if i % 3 == 1 {
                    let _ = st.unlock_vault("ConcurPass2026!#$");
                } else {
                    let _ = st.get_current_codes();
                    let _ = st.list_account_summaries();
                    let _ = st.get_vault_status();
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked during concurrent stress");
    }

    // Final state sanity check: unlock and verify integrity
    state.unlock_vault("ConcurPass2026!#$").unwrap();
    assert!(!state.is_locked());
    let summaries = state.list_account_summaries().unwrap();
    assert_eq!(summaries.len(), 1);

    cleanup_test_dir(&dir);
}

#[test]
fn test_uninitialized_state_security_and_initialization_zero_leak() {
    let dir = create_test_dir("uninit_security");
    let vault_file = dir.join("vault.enc");
    let state = AppState::with_path(vault_file.clone());

    // 1. Initial fresh state must be uninitialized, locked, with 0 accounts
    let status = state.get_vault_status();
    assert!(!status.initialized, "Fresh vault must not be marked initialized");
    assert!(status.locked, "Fresh vault must be locked");
    assert_eq!(status.account_count, 0, "Fresh vault must have 0 accounts");
    assert!(state.is_locked(), "is_locked() must return true");

    // 2. Secret-bearing calls must return error when locked
    assert!(state.get_current_codes().is_err(), "Must reject get_current_codes when uninitialized/locked");
    assert!(state.list_account_summaries().is_err(), "Must reject list_account_summaries when uninitialized/locked");

    // 3. Initialize vault with user password
    let password = "FreshVaultPassword2026!#$";
    state.init_vault(password).expect("init_vault should succeed on fresh path");

    // 4. After initialization, vault is initialized, unlocked, and has 0 accounts (no leaked test accounts!)
    let post_init_status = state.get_vault_status();
    assert!(post_init_status.initialized, "Vault must be marked initialized after init_vault");
    assert!(!post_init_status.locked, "Vault must be unlocked after init_vault");
    assert_eq!(post_init_status.account_count, 0, "Initialized vault must start with 0 accounts");
    assert_eq!(state.list_account_summaries().unwrap().len(), 0, "Account summaries must be empty");

    // 5. Lock and unlock roundtrip
    state.lock_vault().expect("lock_vault should succeed");
    assert!(state.is_locked(), "State must be locked after lock_vault");
    assert_eq!(state.get_vault_status().account_count, 0);

    state.unlock_vault(password).expect("unlock_vault should succeed with correct password");
    assert!(!state.is_locked(), "State must be unlocked after unlock_vault");
    assert_eq!(state.get_vault_status().account_count, 0);

    cleanup_test_dir(&dir);
}
