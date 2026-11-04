//! AuthDesk - Estado global de la aplicación en memoria.
//! Provee acceso concurrente seguro (RwLock) a las cuentas y genera códigos TOTP activos.

use std::sync::RwLock;

use crate::error::AuthDeskError;
use crate::models::{Account, AccountCodeDto, AccountSummaryDto, AccountType, Algorithm};
use crate::otp::totp::{calculate_remaining_seconds, generate_totp};

/// Estado principal de la aplicación gestionado por Tauri.
pub struct AppState {
    pub accounts: RwLock<Vec<Account>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Inicializa el estado con las cuentas de prueba representativas.
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(Self::default_test_accounts()),
        }
    }

    /// Inicializa con una lista explícita de cuentas (útil para pruebas unitarias).
    pub fn with_accounts(accounts: Vec<Account>) -> Self {
        Self {
            accounts: RwLock::new(accounts),
        }
    }

    /// Cuentas de prueba hardcodeadas para el desarrollo de la Fase 1.
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
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(), // RFC 6238 20B
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
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====".to_string(), // RFC 6238 32B
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
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=".to_string(), // RFC 6238 64B
                algorithm: Algorithm::Sha512,
                digits: 8,
                period: 60,
                account_type: AccountType::Totp,
                counter: None,
            },
        ]
    }

    /// Devuelve los códigos TOTP correspondientes al instante actual (`SystemTime::now`).
    pub fn get_current_codes(&self) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.get_codes_at(now)
    }

    /// Calcula y devuelve los códigos TOTP para un timestamp Unix exacto.
    /// Permite pruebas deterministas sin depender del reloj del sistema.
    pub fn get_codes_at(&self, timestamp: u64) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
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

    /// Retorna los resúmenes de cuentas (metadatos sin secretos).
    pub fn list_account_summaries(&self) -> Result<Vec<AccountSummaryDto>, AuthDeskError> {
        let accounts = self.accounts.read()?;
        Ok(accounts.iter().map(|a| a.to_summary_dto()).collect())
    }

    /// Agrega una nueva cuenta al estado.
    pub fn add_account(&self, account: Account) -> Result<(), AuthDeskError> {
        let mut accounts = self.accounts.write()?;
        accounts.push(account);
        Ok(())
    }

    /// Elimina una cuenta por su identificador. Retorna true si fue encontrada y eliminada.
    pub fn delete_account(&self, id: &str) -> Result<bool, AuthDeskError> {
        let mut accounts = self.accounts.write()?;
        let initial_len = accounts.len();
        accounts.retain(|a| a.id != id);
        Ok(accounts.len() < initial_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_default_accounts_valid() {
        let state = AppState::new();
        let accounts = state.accounts.read().unwrap();
        assert!(accounts.len() >= 4, "Debe tener al menos 4 cuentas de prueba");

        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"test-github-1"));
        assert!(ids.contains(&"test-google-2"));
        assert!(ids.contains(&"test-aws-3"));
        assert!(ids.contains(&"test-proton-4"));
    }

    #[test]
    fn test_state_countdown_boundaries() {
        let state = AppState::new();

        // En T=300 (múltiplo de 30):
        let codes_300 = state.get_codes_at(300).expect("Debe calcular códigos");
        for c in codes_300.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 30);
        }

        // En T=315 (mitad de ciclo de 30s):
        let codes_315 = state.get_codes_at(315).expect("Debe calcular códigos");
        for c in codes_315.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 15);
        }

        // En T=329 (último segundo de ciclo de 30s):
        let codes_329 = state.get_codes_at(329).expect("Debe calcular códigos");
        for c in codes_329.iter().filter(|c| c.period == 30) {
            assert_eq!(c.seconds_remaining, 1);
        }
    }

    #[test]
    fn test_state_rfc_vectors_matching() {
        let state = AppState::new();

        // Evaluar en T = 1234567890
        let codes = state.get_codes_at(1234567890).expect("Debe calcular códigos");

        // Cuenta AWS: SHA1, 6 dígitos, T=1234567890 -> código "005924"
        let aws = codes.iter().find(|c| c.id == "test-aws-3").unwrap();
        assert_eq!(aws.code, "005924");
        assert_eq!(aws.digits, 6);

        // Cuenta Proton: SHA256, 8 dígitos, T=1234567890 -> código "91819424"
        let proton = codes.iter().find(|c| c.id == "test-proton-4").unwrap();
        assert_eq!(proton.code, "91819424");
        assert_eq!(proton.digits, 8);
    }

    #[test]
    fn test_state_add_and_delete() {
        let state = AppState::new();
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
        let state = AppState::new();
        let summaries = state.list_account_summaries().unwrap();
        assert_eq!(summaries.len(), state.accounts.read().unwrap().len());

        let json = serde_json::to_string(&summaries).unwrap();
        assert!(!json.contains("secret"));
    }
}
