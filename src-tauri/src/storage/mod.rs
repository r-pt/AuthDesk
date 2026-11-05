// [ENC-B64::cnB0|Z2Ft|cm9k]
pub mod atomic;
pub mod vault_file;

pub use atomic::{
    atomic_write_file, default_vault_dir, default_vault_path, ensure_vault_dir,
    harden_dir_permissions, harden_file_permissions, safe_read_file,
};
pub use vault_file::{EncryptedBlob, KdfConfig, VaultEnvelope, VaultPayload};
