//! AuthDesk - Modelos de datos del dominio TOTP y DTOs para IPC.
//! Invariante de seguridad: Las claves secretas nunca se transfieren al frontend ni se exponen en Debug.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::AuthDeskError;

/// Algoritmo criptográfico de hashing soportado según RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Sha1
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Sha1 => write!(f, "SHA1"),
            Algorithm::Sha256 => write!(f, "SHA256"),
            Algorithm::Sha512 => write!(f, "SHA512"),
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = AuthDeskError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().trim() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            other => Err(AuthDeskError::InvalidParameter(format!(
                "Algoritmo no soportado: {}",
                other
            ))),
        }
    }
}

/// Tipo de cuenta de un solo uso (TOTP o HOTP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccountType {
    Totp,
    Hotp,
}

impl Default for AccountType {
    fn default() -> Self {
        AccountType::Totp
    }
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::Totp => write!(f, "TOTP"),
            AccountType::Hotp => write!(f, "HOTP"),
        }
    }
}

/// Cuenta TOTP almacenada en memoria o en la bóveda segura.
/// Contiene el secreto Base32 sensible. Nunca debe exponerse vía IPC.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub secret: String, // Clave secreta Base32 sensible
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub account_type: AccountType,
    pub counter: Option<u64>,
}

impl Account {
    /// Crea una nueva cuenta validando restricciones de dominio.
    pub fn new(
        id: String,
        issuer: String,
        account: String,
        secret: String,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
        account_type: AccountType,
        counter: Option<u64>,
    ) -> Result<Self, AuthDeskError> {
        if digits != 6 && digits != 8 {
            return Err(AuthDeskError::InvalidParameter(format!(
                "La longitud de dígitos debe ser 6 u 8, se recibió: {}",
                digits
            )));
        }
        if period == 0 {
            return Err(AuthDeskError::InvalidParameter(
                "El período debe ser mayor a 0 segundos".to_string(),
            ));
        }
        if secret.trim().is_empty() {
            return Err(AuthDeskError::InvalidParameter(
                "El secreto Base32 no puede estar vacío".to_string(),
            ));
        }

        Ok(Self {
            id,
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            account_type,
            counter,
        })
    }

    /// Convierte la cuenta en un DTO seguro con el código actual para la paleta.
    pub fn to_code_dto(&self, code: String, seconds_remaining: u64) -> AccountCodeDto {
        AccountCodeDto {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            code,
            seconds_remaining,
            period: self.period,
            digits: self.digits,
            algorithm: self.algorithm,
        }
    }

    /// Convierte la cuenta en un DTO de resumen (metadatos sin secretos).
    pub fn to_summary_dto(&self) -> AccountSummaryDto {
        AccountSummaryDto {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            digits: self.digits,
            period: self.period,
            algorithm: self.algorithm,
            account_type: self.account_type,
        }
    }
}

/// Implementación manual de Debug que oculta el secreto mediante [REDACTED].
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("account_type", &self.account_type)
            .field("counter", &self.counter)
            .finish()
    }
}

/// DTO para la paleta de códigos en el frontend (Tauri IPC).
/// Devuelve el código calculado, tiempo restante y metadatos visuales sin secretos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCodeDto {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
}

/// DTO de resumen de cuenta para operaciones de listado (sin secretos ni códigos).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummaryDto {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
    pub account_type: AccountType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_debug_redaction() {
        let secret = "JBSWY3DPEHPK3PXP";
        let account = Account::new(
            "acc-1".to_string(),
            "GitHub".to_string(),
            "user@github.com".to_string(),
            secret.to_string(),
            Algorithm::Sha1,
            6,
            30,
            AccountType::Totp,
            None,
        )
        .expect("Creación válida");

        let debug_str = format!("{:?}", account);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(secret));
    }

    #[test]
    fn test_account_validation_rejection() {
        // Dígitos inválidos (debe ser 6 u 8)
        assert!(Account::new(
            "1".into(), "Iss".into(), "Acc".into(), "SECRET".into(),
            Algorithm::Sha1, 5, 30, AccountType::Totp, None
        ).is_err());

        assert!(Account::new(
            "1".into(), "Iss".into(), "Acc".into(), "SECRET".into(),
            Algorithm::Sha1, 7, 30, AccountType::Totp, None
        ).is_err());

        // Período 0
        assert!(Account::new(
            "1".into(), "Iss".into(), "Acc".into(), "SECRET".into(),
            Algorithm::Sha1, 6, 0, AccountType::Totp, None
        ).is_err());

        // Secreto vacío
        assert!(Account::new(
            "1".into(), "Iss".into(), "Acc".into(), "   ".into(),
            Algorithm::Sha1, 6, 30, AccountType::Totp, None
        ).is_err());
    }

    #[test]
    fn test_dto_has_no_secret_field() {
        let dto = AccountCodeDto {
            id: "id-123".to_string(),
            issuer: "Google".to_string(),
            account: "test@gmail.com".to_string(),
            code: "123456".to_string(),
            seconds_remaining: 28,
            period: 30,
            digits: 6,
            algorithm: Algorithm::Sha1,
        };

        let json = serde_json::to_string(&dto).expect("Debe serializar");
        assert!(!json.contains("secret"));
        assert!(!json.contains("password"));
        assert!(json.contains("\"code\":\"123456\""));
        assert!(json.contains("\"seconds_remaining\":28"));
    }

    #[test]
    fn test_algorithm_display_and_from_str() {
        assert_eq!(Algorithm::Sha1.to_string(), "SHA1");
        assert_eq!(Algorithm::Sha256.to_string(), "SHA256");
        assert_eq!(Algorithm::Sha512.to_string(), "SHA512");

        assert_eq!("sha1".parse::<Algorithm>().unwrap(), Algorithm::Sha1);
        assert_eq!("SHA256".parse::<Algorithm>().unwrap(), Algorithm::Sha256);
        assert_eq!("Sha512".parse::<Algorithm>().unwrap(), Algorithm::Sha512);
        assert!("MD5".parse::<Algorithm>().is_err());
    }
}
