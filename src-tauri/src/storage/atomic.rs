// [ENC-B64::cnB0|Z2Ft|cm9k]
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use crate::error::AuthDeskError;
use crate::storage::vault_file::VaultEnvelope;

pub fn default_vault_dir() -> PathBuf {
    if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
        if !xdg_data.trim().is_empty() {
            return PathBuf::from(xdg_data).join("authdesk");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".local").join("share").join("authdesk");
        }
    }
    PathBuf::from("/tmp").join("authdesk")
}

pub fn default_vault_path() -> PathBuf {
    default_vault_dir().join("vault.enc")
}

pub fn harden_dir_permissions(path: &Path) -> Result<(), AuthDeskError> {
    if path.exists() {
        let meta = std::fs::metadata(path).map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        }
    }
    Ok(())
}

pub fn harden_file_permissions(path: &Path) -> Result<(), AuthDeskError> {
    if path.exists() {
        let meta = std::fs::metadata(path).map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
        }
    }
    Ok(())
}

pub fn ensure_vault_dir(dir: &Path) -> Result<(), AuthDeskError> {
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| AuthDeskError::Vault(e.to_string()))?;
    } else {
        harden_dir_permissions(dir)?;
    }
    Ok(())
}

pub fn atomic_write_file(path: &Path, content: &[u8]) -> Result<(), AuthDeskError> {
    let parent = path.parent().ok_or_else(|| {
        AuthDeskError::Vault("Vault path has no parent directory".to_string())
    })?;
    ensure_vault_dir(parent)?;

    let tmp_file_name = format!(
        "vault.enc.tmp.{}_{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let tmp_path = parent.join(tmp_file_name);

    let write_res = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(AuthDeskError::Vault(format!(
            "Failed writing temporary vault file: {}",
            e
        )));
    }

    if path.exists() {
        let backup_path = parent.join("vault.enc.bak");
        if let Ok(_) = std::fs::copy(path, &backup_path) {
            let _ = std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600));
            if let Ok(bak_file) = File::open(&backup_path) {
                let _ = bak_file.sync_all();
            }
        }
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(AuthDeskError::Vault(format!(
            "Failed atomic rename to vault file: {}",
            e
        )));
    }

    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    harden_file_permissions(path)?;
    Ok(())
}

pub fn safe_read_file(path: &Path) -> Result<Vec<u8>, AuthDeskError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let backup_path = parent.join("vault.enc.bak");

    if path.exists() {
        let _ = harden_file_permissions(path);
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(env) = serde_json::from_slice::<VaultEnvelope>(&bytes) {
                if env.validate().is_ok() {
                    return Ok(bytes);
                }
            }
        }

        if backup_path.exists() {
            let _ = harden_file_permissions(&backup_path);
            if let Ok(bak_bytes) = std::fs::read(&backup_path) {
                if let Ok(bak_env) = serde_json::from_slice::<VaultEnvelope>(&bak_bytes) {
                    if bak_env.validate().is_ok() {
                        let _ = std::fs::copy(&backup_path, path);
                        let _ = harden_file_permissions(path);
                        log::warn!(
                            "Bóveda principal corrupta; restaurada exitosamente desde copia de seguridad .bak"
                        );
                        return Ok(bak_bytes);
                    }
                }
            }
        }
        return Err(AuthDeskError::Vault(
            "Bóveda corrupta y no se pudo restaurar desde copia de seguridad".to_string(),
        ));
    }

    if backup_path.exists() {
        let _ = harden_file_permissions(&backup_path);
        if let Ok(bak_bytes) = std::fs::read(&backup_path) {
            if let Ok(bak_env) = serde_json::from_slice::<VaultEnvelope>(&bak_bytes) {
                if bak_env.validate().is_ok() {
                    let _ = std::fs::copy(&backup_path, path);
                    let _ = harden_file_permissions(path);
                    return Ok(bak_bytes);
                }
            }
        }
    }

    Err(AuthDeskError::Vault("Archivo de bóveda no encontrado".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_creates_file_with_0600_perms() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_perms_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");

        atomic_write_file(&vault_file, b"test content").unwrap();

        let dir_meta = std::fs::metadata(&tmp_dir).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

        let file_meta = std::fs::metadata(&vault_file).unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_atomic_write_rotates_existing_file_to_bak() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_bak_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");
        let backup_file = tmp_dir.join("vault.enc.bak");

        atomic_write_file(&vault_file, b"VERSION_1").unwrap();
        atomic_write_file(&vault_file, b"VERSION_2").unwrap();

        assert_eq!(std::fs::read_to_string(&vault_file).unwrap(), "VERSION_2");
        assert_eq!(std::fs::read_to_string(&backup_file).unwrap(), "VERSION_1");

        let bak_meta = std::fs::metadata(&backup_file).unwrap();
        assert_eq!(bak_meta.permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_loose_permissions_hardening() {
        let tmp_dir = std::env::temp_dir().join(format!("authdesk_test_harden_{}", rand::random::<u64>()));
        let vault_file = tmp_dir.join("vault.enc");
        atomic_write_file(&vault_file, b"sample").unwrap();

        std::fs::set_permissions(&vault_file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(std::fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777, 0o666);

        harden_file_permissions(&vault_file).unwrap();
        assert_eq!(std::fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
